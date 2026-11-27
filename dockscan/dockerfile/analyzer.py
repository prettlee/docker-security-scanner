"""Static security analyzer for Dockerfiles (separate from built-image scanning)."""

from pathlib import Path
from typing import List, Optional, Set

from dockscan.dockerfile.parser import (
    BuildStage,
    ParsedDockerfile,
    parse_dockerfile_file,
    parse_dockerfile_text,
)
from dockscan.dockerfile.security_checks import (
    check_hardcoded_credentials,
    check_insecure_install_commands,
    check_unpinned_dependencies,
)
from dockscan.models.finding import Finding, ScanReport
from dockscan.reporting import aggregate_findings, score_confidence


def make_dockerfile_finding(
    *,
    rule_id: str,
    title: str,
    severity: str,
    location: str,
    evidence: str,
    description: str,
    remediation: str,
    file_path: str,
    line_number: Optional[int] = None,
    category: str = "misconfiguration",
    confidence_score: float = 0.95,
) -> Finding:
    """Create a normalized Finding for a static Dockerfile check."""
    label, score = score_confidence(
        detector="config", explicit_score=confidence_score
    )
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=label,
        confidence_score=score,
        source="dockerfile",
        location=location,
        redacted_secret=evidence,
        description=description,
        remediation=remediation,
        detector="dockerfile",
        category=category,
        file_path=file_path,
        line_number=line_number,
    )


def check_latest_tags(parsed: ParsedDockerfile) -> List[Finding]:
    """DF-001: Detect `FROM <image>:latest` or untagged base images."""
    findings: List[Finding] = []
    seen_aliases: Set[str] = set()

    for stage in parsed.stages:
        image = stage.base_image
        if not image:
            continue
        if image.lower() == "scratch" or image in seen_aliases:
            if stage.alias:
                seen_aliases.add(stage.alias)
            continue

        if stage.alias:
            seen_aliases.add(stage.alias)

        if "@sha256:" in image or "@sha512:" in image:
            continue

        last_segment = image.rsplit("/", 1)[-1]
        has_tag = ":" in last_segment
        tag = last_segment.split(":", 1)[1] if has_tag else ""

        if has_tag and tag.lower() == "latest":
            findings.append(
                make_dockerfile_finding(
                    rule_id="DF-001",
                    title="Base image uses explicit ':latest' tag",
                    severity="High",
                    location=f"{parsed.path}:{stage.from_line}",
                    evidence=f"FROM {image}",
                    description=(
                        "Using ':latest' makes builds non-reproducible and can silently pull "
                        "breaking changes or newly introduced vulnerabilities."
                    ),
                    remediation="Pin the base image to an immutable version tag and/or SHA256 digest.",
                    file_path=parsed.path,
                    line_number=stage.from_line,
                    confidence_score=1.0,
                )
            )
        elif not has_tag and not image.startswith("$"):
            findings.append(
                make_dockerfile_finding(
                    rule_id="DF-001",
                    title="Base image omits version tag (defaults to ':latest')",
                    severity="Medium",
                    location=f"{parsed.path}:{stage.from_line}",
                    evidence=f"FROM {image}",
                    description=(
                        "Omitting an explicit tag causes Docker to pull ':latest' by default, "
                        "making builds non-deterministic."
                    ),
                    remediation="Specify an explicit, immutable version tag or SHA256 digest in `FROM`.",
                    file_path=parsed.path,
                    line_number=stage.from_line,
                    confidence_score=0.95,
                )
            )

    return findings


def check_non_root_user(parsed: ParsedDockerfile) -> List[Finding]:
    """DF-002: Flag final build stage missing a non-root USER directive."""
    if not parsed.stages:
        return []

    final_stage: BuildStage = parsed.stages[-1]
    user_instrs = [
        instr for instr in final_stage.instructions if instr.instruction == "USER"
    ]
    if not user_instrs:
        return [
            make_dockerfile_finding(
                rule_id="DF-002",
                title="Missing non-root USER directive",
                severity="High",
                location=f"{parsed.path}:{final_stage.from_line}",
                evidence=f"Final stage (FROM {final_stage.base_image}) has no USER directive",
                description=(
                    "Without a non-root `USER` directive, containers built from this Dockerfile "
                    "will run as root (UID 0), increasing the impact of a container escape."
                ),
                remediation="Create a dedicated non-root user and add `USER <non-root-user>` before CMD/ENTRYPOINT.",
                file_path=parsed.path,
                line_number=final_stage.from_line,
                confidence_score=1.0,
            )
        ]

    last_user = user_instrs[-1]
    user_part = last_user.arguments.split(":", 1)[0].strip()
    if user_part in ("", "root", "0"):
        return [
            make_dockerfile_finding(
                rule_id="DF-002",
                title="Final stage USER directive runs as root",
                severity="High",
                location=f"{parsed.path}:{last_user.line_number}",
                evidence=f"USER {last_user.arguments}",
                description=(
                    "The final `USER` directive sets the runtime user to root (UID 0)."
                ),
                remediation="Switch to a non-root user (e.g., `USER appuser` or `USER 10001`).",
                file_path=parsed.path,
                line_number=last_user.line_number,
                confidence_score=1.0,
            )
        ]
    return []


def check_unsafe_add(parsed: ParsedDockerfile) -> List[Finding]:
    """DF-004: Flag `ADD` instructions (remote URLs and implicit archive extraction)."""
    findings: List[Finding] = []

    for instr in parsed.instructions:
        if instr.instruction != "ADD":
            continue

        tokens = [t for t in instr.arguments.split() if not t.startswith("--")]
        is_remote = any(
            t.lower().startswith(("http://", "https://")) for t in tokens[:-1]
        )
        if is_remote:
            findings.append(
                make_dockerfile_finding(
                    rule_id="DF-004",
                    title="Unsafe ADD instruction fetching remote URL",
                    severity="High",
                    location=f"{parsed.path}:{instr.line_number}",
                    evidence=instr.raw,
                    description=(
                        "`ADD` with a remote URL downloads unverified remote artifacts without "
                        "checksum verification and increases supply-chain risk."
                    ),
                    remediation=(
                        "Replace remote `ADD` with `curl`/`wget` over HTTPS + SHA256 checksum "
                        "verification in a single `RUN` layer, or use `COPY` for local files."
                    ),
                    file_path=parsed.path,
                    line_number=instr.line_number,
                    confidence_score=0.95,
                )
            )
        else:
            findings.append(
                make_dockerfile_finding(
                    rule_id="DF-004",
                    title="Prefer COPY over ADD for local files",
                    severity="Medium",
                    location=f"{parsed.path}:{instr.line_number}",
                    evidence=instr.raw,
                    description=(
                        "`ADD` automatically extracts local compressed archives, which can cause "
                        "unexpected file overwrites or tar-slip vulnerabilities."
                    ),
                    remediation="Use `COPY` instead of `ADD` unless archive extraction is explicitly required.",
                    file_path=parsed.path,
                    line_number=instr.line_number,
                    confidence_score=0.90,
                )
            )

    return findings


def check_missing_healthcheck(parsed: ParsedDockerfile) -> List[Finding]:
    """DF-007: Flag final stage missing an active HEALTHCHECK directive."""
    if not parsed.stages:
        return []

    final_stage = parsed.stages[-1]
    healthchecks = [
        instr for instr in final_stage.instructions if instr.instruction == "HEALTHCHECK"
    ]
    if not healthchecks:
        return [
            make_dockerfile_finding(
                rule_id="DF-007",
                title="Missing HEALTHCHECK instruction",
                severity="Low",
                location=f"{parsed.path}:{final_stage.from_line}",
                evidence=f"Final stage (FROM {final_stage.base_image}) has no HEALTHCHECK",
                description=(
                    "Without a `HEALTHCHECK` instruction, Docker cannot automatically detect when "
                    "the containerized application becomes unresponsive or unhealthy."
                ),
                remediation="Add a `HEALTHCHECK` instruction (e.g., `HEALTHCHECK CMD curl -f http://localhost/ || exit 1`).",
                file_path=parsed.path,
                line_number=final_stage.from_line,
                confidence_score=1.0,
            )
        ]

    if healthchecks[-1].arguments.strip().upper().startswith("NONE"):
        return [
            make_dockerfile_finding(
                rule_id="DF-007",
                title="HEALTHCHECK explicitly disabled (HEALTHCHECK NONE)",
                severity="Low",
                location=f"{parsed.path}:{healthchecks[-1].line_number}",
                evidence=healthchecks[-1].raw,
                description="Health checking is explicitly disabled in the final stage.",
                remediation="Configure an application-specific `HEALTHCHECK` command.",
                file_path=parsed.path,
                line_number=healthchecks[-1].line_number,
                confidence_score=1.0,
            )
        ]

    return []


def _analyze_parsed(parsed: ParsedDockerfile) -> ScanReport:
    """Run all configured Dockerfile security checks against `parsed`."""
    raw_findings: List[Finding] = []
    raw_findings.extend(check_latest_tags(parsed))
    raw_findings.extend(check_non_root_user(parsed))
    raw_findings.extend(check_hardcoded_credentials(parsed))
    raw_findings.extend(check_unsafe_add(parsed))
    raw_findings.extend(check_unpinned_dependencies(parsed))
    raw_findings.extend(check_insecure_install_commands(parsed))
    raw_findings.extend(check_missing_healthcheck(parsed))

    return ScanReport(
        target=parsed.path,
        image_id="dockerfile-static",
        layers_scanned=len(parsed.stages),
        files_scanned=1,
        packages_scanned=0,
        findings=aggregate_findings(raw_findings),
    )


def analyze_dockerfile_text(content: str, path: str = "Dockerfile") -> ScanReport:
    """Analyze Dockerfile text and return a unified `ScanReport`."""
    return _analyze_parsed(parse_dockerfile_text(content, path=path))


def analyze_dockerfile_file(path: Path) -> ScanReport:
    """Analyze a Dockerfile on disk and return a unified `ScanReport`."""
    return _analyze_parsed(parse_dockerfile_file(path))
