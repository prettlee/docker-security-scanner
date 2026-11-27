"""Dangerous and publicly exposed port security check."""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from scanner.models import Finding, ImageMetadata, PortBinding


@dataclass(frozen=True)
class DangerousPortRule:
    """Metadata describing why a specific port is risky when exposed."""

    service: str
    category: str  # "ssh", "docker_api", or "database"
    severity: str
    reason: str
    remediation: str


DANGEROUS_PORTS: Dict[int, DangerousPortRule] = {
    22: DangerousPortRule(
        service="SSH",
        category="ssh",
        severity="HIGH",
        reason=(
            "Exposing SSH (port 22) inside a container encourages interactive remote "
            "shell access, expands the attack surface, and increases credential/key "
            "compromise risk."
        ),
        remediation=(
            "Remove the SSH server from the image, drop `EXPOSE 22`, and use "
            "`docker exec` or orchestrator debugging tools when needed."
        ),
    ),
    2375: DangerousPortRule(
        service="Docker Daemon API (unencrypted)",
        category="docker_api",
        severity="CRITICAL",
        reason=(
            "Port 2375 is the unencrypted, unauthenticated Docker daemon API. "
            "Exposing it grants anyone who can reach the port root-equivalent "
            "control over the host."
        ),
        remediation=(
            "Never expose port 2375. Remove `EXPOSE 2375` and disable unauthenticated "
            "TCP daemon sockets (or require mutual TLS on port 2376 restricted to "
            "trusted networks)."
        ),
    ),
    1433: DangerousPortRule(
        service="Microsoft SQL Server",
        category="database",
        severity="HIGH",
        reason="Exposing a database port publicly increases exposure to brute-force and protocol attacks.",
        remediation="Bind database ports to an internal Docker network or `127.0.0.1` instead of public interfaces.",
    ),
    1521: DangerousPortRule(
        service="Oracle Database",
        category="database",
        severity="HIGH",
        reason="Exposing a database port publicly increases exposure to brute-force and protocol attacks.",
        remediation="Bind database ports to an internal Docker network or `127.0.0.1` instead of public interfaces.",
    ),
    3306: DangerousPortRule(
        service="MySQL / MariaDB",
        category="database",
        severity="HIGH",
        reason="Exposing a database port publicly increases exposure to brute-force and protocol attacks.",
        remediation="Bind database ports to an internal Docker network or `127.0.0.1` instead of public interfaces.",
    ),
    5432: DangerousPortRule(
        service="PostgreSQL",
        category="database",
        severity="HIGH",
        reason="Exposing a database port publicly increases exposure to brute-force and protocol attacks.",
        remediation="Bind database ports to an internal Docker network or `127.0.0.1` instead of public interfaces.",
    ),
    5984: DangerousPortRule(
        service="CouchDB",
        category="database",
        severity="HIGH",
        reason="Exposing a database port publicly increases exposure to brute-force and unauthenticated access.",
        remediation="Bind database ports to an internal Docker network or `127.0.0.1` instead of public interfaces.",
    ),
    6379: DangerousPortRule(
        service="Redis",
        category="database",
        severity="HIGH",
        reason="Exposing Redis publicly risks unauthenticated data access and remote exploitation.",
        remediation="Keep Redis on an internal Docker network or bind to `127.0.0.1` with authentication enabled.",
    ),
    9042: DangerousPortRule(
        service="Apache Cassandra",
        category="database",
        severity="HIGH",
        reason="Exposing a database port publicly increases exposure to unauthorized cluster/data access.",
        remediation="Bind database ports to an internal Docker network or `127.0.0.1` instead of public interfaces.",
    ),
    9200: DangerousPortRule(
        service="Elasticsearch HTTP",
        category="database",
        severity="HIGH",
        reason="Exposing Elasticsearch publicly can leak indexed data or allow unauthorized cluster modification.",
        remediation="Keep Elasticsearch on an internal network or bind strictly to `127.0.0.1` behind authentication.",
    ),
    9300: DangerousPortRule(
        service="Elasticsearch Transport",
        category="database",
        severity="HIGH",
        reason="Exposing Elasticsearch inter-node transport publicly risks unauthorized cluster joins and data access.",
        remediation="Restrict Elasticsearch transport ports to private cluster networks.",
    ),
    11211: DangerousPortRule(
        service="Memcached",
        category="database",
        severity="HIGH",
        reason="Exposing Memcached publicly risks unauthenticated cache leaks and UDP amplification attacks.",
        remediation="Keep Memcached on an internal Docker network or bind strictly to `127.0.0.1`.",
    ),
    27017: DangerousPortRule(
        service="MongoDB",
        category="database",
        severity="HIGH",
        reason="Exposing MongoDB publicly risks unauthorized database access and ransomware/data theft.",
        remediation="Bind MongoDB to an internal Docker network or `127.0.0.1` with authentication enabled.",
    ),
}


def _parse_port_number(port_spec: str) -> Optional[int]:
    """Extract numeric port from a Docker port string such as '5432/tcp'."""
    port_str = port_spec.split("/", 1)[0].strip()
    if not port_str.isdigit():
        return None
    return int(port_str)


def check_dangerous_ports(metadata: ImageMetadata) -> List[Finding]:
    """Flag SSH (22), Docker API (2375), and publicly exposed database ports."""
    bindings_by_port: Dict[str, List[PortBinding]] = {}
    for binding in metadata.port_bindings:
        bindings_by_port.setdefault(binding.container_port, []).append(binding)

    # Preserve order while checking both declared ExposedPorts and PortBindings.
    candidate_ports: List[str] = list(metadata.exposed_ports)
    for port_spec in bindings_by_port:
        if port_spec not in candidate_ports:
            candidate_ports.append(port_spec)

    findings: List[Finding] = []
    seen_ports: set[Tuple[str, int]] = set()

    for port_spec in candidate_ports:
        port_num = _parse_port_number(port_spec)
        if port_num is None or port_num not in DANGEROUS_PORTS:
            continue

        key = (port_spec, port_num)
        if key in seen_ports:
            continue
        seen_ports.add(key)

        rule = DANGEROUS_PORTS[port_num]
        port_bindings = bindings_by_port.get(port_spec, [])

        if port_bindings:
            public_bindings = [b for b in port_bindings if b.is_public]
            # For database ports on running containers, only flag public bindings.
            if rule.category == "database" and not public_bindings:
                continue

            relevant = public_bindings if public_bindings else port_bindings
            formatted = ", ".join(
                f"{b.host_ip or '0.0.0.0'}:{b.host_port}->{b.container_port}"
                for b in relevant
            )
            evidence = f"HostConfig.PortBindings = {formatted}"
        else:
            evidence = f"Config.ExposedPorts includes {port_spec}"

        if rule.category == "database":
            title = f"Database port {port_num} ({rule.service}) exposed publicly"
        else:
            title = f"Dangerous port {port_num} ({rule.service}) exposed"

        findings.append(
            Finding(
                rule_id="DOCKER-002",
                severity=rule.severity,
                title=title,
                description=rule.reason,
                remediation=rule.remediation,
                evidence=evidence,
            )
        )

    return findings
