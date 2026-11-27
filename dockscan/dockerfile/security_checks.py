"""Dockerfile checks for hardcoded credentials, unpinned dependencies, and insecure installs."""

from pathlib import Path
import re
import shlex
from typing import List, Optional, Sequence, Tuple

from dockscan.dockerfile.parser import ParsedDockerfile
from dockscan.models.finding import Finding, redact_secret
from dockscan.reporting import score_confidence
from dockscan.secrets.pattern_detector import detect_patterns_in_text
from dockscan.secrets.rules import SUSPICIOUS_KEY_INDICATORS, is_placeholder

_PIPE_TO_SHELL_RE = re.compile(
    r"(?i)\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:env\s+)?(?:sh|bash|zsh|ash|dash|python3?|perl|ruby)\b"
)
_HTTP_DOWNLOAD_RE = re.compile(
    r"(?i)\b(?:curl|wget)\b[^\n]*?\b(http://(?!localhost\b|127\.0\.0\.1\b)[^\s\"']+)"
)
_CHMOD_777_RE = re.compile(
    r"(?i)\bchmod\b(?:\s+-[A-Za-z]+)*\s+(?:0?777|a\+rwx)\b"
)
_INSECURE_TLS_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\bcurl\b[^\n]*(?:\s-k\b|--insecure\b)"), "curl TLS verification disabled (-k/--insecure)"),
    (re.compile(r"(?i)\bwget\b[^\n]*--no-check-certificate\b"), "wget TLS verification disabled (--no-check-certificate)"),
    (re.compile(r"(?i)\bpip3?\b[^\n]*--trusted-host\b"), "pip TLS verification bypassed (--trusted-host)"),
    (re.compile(r"(?i)\bnpm\b[^\n]*strict-ssl\s+false\b"), "npm TLS verification disabled (strict-ssl false)"),
    (re.compile(r"\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0[\"']?"), "Node.js TLS verification disabled (NODE_TLS_REJECT_UNAUTHORIZED=0)"),
    (re.compile(r"(?i)\bapt(?:-get)?\b[^\n]*--allow-unauthenticated\b"), "apt signature verification bypassed (--allow-unauthenticated)"),
    (re.compile(r"(?i)\bapk\b[^\n]*--allow-untrusted\b"), "apk signature verification bypassed (--allow-untrusted)"),
)
_SHELL_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||;)\s*")


def _make_finding(
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


def _parse_kv_assignments(arguments: str) -> List[Tuple[str, str]]:
    """Parse `ENV`/`ARG`/`LABEL` key=value or `ENV KEY VALUE` forms."""
    if "=" not in arguments:
        parts = arguments.split(None, 1)
        return [(parts[0], parts[1])] if len(parts) == 2 else []

    try:
        tokens = shlex.split(arguments)
    except ValueError:
        tokens = arguments.split()

    pairs: List[Tuple[str, str]] = []
    for tok in tokens:
        if "=" in tok:
            key, val = tok.split("=", 1)
            pairs.append((key, val))
    return pairs


def check_hardcoded_credentials(parsed: ParsedDockerfile) -> List[Finding]:
    """DF-003 / SEC-*: Detect hardcoded secrets in ENV, ARG, LABEL, and RUN instructions."""
    findings: List[Finding] = []

    for instr in parsed.instructions:
        if instr.instruction not in ("ENV", "ARG", "LABEL", "RUN"):
            continue

        location = f"{parsed.path}:{instr.line_number}"
        pattern_matches = detect_patterns_in_text(
            instr.arguments,
            source="dockerfile",
            location_prefix=location,
            file_path=parsed.path,
            include_line_numbers=False,
        )
        for pm in pattern_matches:
            pm.finding.line_number = instr.line_number
            pm.finding.location = location
            pm.finding.category = "secret"
            findings.append(pm.finding)

        if instr.instruction in ("ENV", "ARG", "LABEL") and not pattern_matches:
            for key, value in _parse_kv_assignments(instr.arguments):
                if is_placeholder(value) or value.startswith("$"):
                    continue
                upper_key = key.upper()
                matched_ind = [
                    ind for ind in SUSPICIOUS_KEY_INDICATORS if ind in upper_key
                ]
                if matched_ind:
                    findings.append(
                        _make_finding(
                            rule_id="DF-003",
                            title=f"Hardcoded credential in Dockerfile {instr.instruction} '{key}'",
                            severity="High",
                            location=location,
                            evidence=f"{instr.instruction} {key}={redact_secret(value)}",
                            description=(
                                f"`{instr.instruction} {key}` assigns a literal value matching secret "
                                f"indicator(s): {', '.join(matched_ind)}."
                            ),
                            remediation=(
                                "Do not bake secrets into `ENV`/`ARG`/`LABEL`. Use BuildKit secret "
                                "mounts (`RUN --mount=type=secret`) during builds or runtime secret injection."
                            ),
                            category="secret",
                            file_path=parsed.path,
                            line_number=instr.line_number,
                            confidence_score=0.80,
                        )
                    )

    return findings


def _tokenize_command(segment: str) -> List[str]:
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def _find_unpinned_in_segment(tokens: Sequence[str]) -> List[Tuple[str, List[str]]]:
    """Inspect a single shell command segment for unpinned package installs."""
    issues: List[Tuple[str, List[str]]] = []
    if not tokens:
        return issues

    if (
        len(tokens) >= 3
        and tokens[0].startswith("python")
        and tokens[1] == "-m"
        and tokens[2] == "pip"
    ):
        cmd = "pip"
        rest = list(tokens[3:])
    else:
        cmd = Path(tokens[0]).name
        rest = list(tokens[1:])

    if cmd in ("pip", "pip3") and "install" in rest:
        sub = rest[rest.index("install") + 1 :]
        unpinned: List[str] = []
        skip_next = False
        for tok in sub:
            if skip_next:
                skip_next = False
                continue
            if tok in (
                "-r",
                "--requirement",
                "-c",
                "--constraint",
                "-t",
                "--target",
                "-i",
                "--index-url",
                "--extra-index-url",
                "--find-links",
                "-f",
            ):
                skip_next = True
                continue
            if (
                tok.startswith("-")
                or tok in (".", "./")
                or tok.endswith((".whl", ".tar.gz", ".zip"))
            ):
                continue
            if "==" not in tok and "===" not in tok and "@" not in tok:
                unpinned.append(tok)
        if unpinned:
            issues.append(("pip", unpinned))

    elif cmd == "npm" and any(sub in rest for sub in ("install", "i", "add")):
        verb_idx = next(i for i, t in enumerate(rest) if t in ("install", "i", "add"))
        sub = rest[verb_idx + 1 :]
        unpinned = []
        for tok in sub:
            if tok.startswith("-"):
                continue
            name_part = tok[1:] if tok.startswith("@") else tok
            if "@" not in name_part:
                unpinned.append(tok)
        if unpinned:
            issues.append(("npm", unpinned))

    elif cmd in ("apt-get", "apt") and "install" in rest:
        sub = rest[rest.index("install") + 1 :]
        unpinned = []
        skip_next = False
        for tok in sub:
            if skip_next:
                skip_next = False
                continue
            if tok in ("-t", "--target-release", "-o"):
                skip_next = True
                continue
            if tok.startswith("-") or tok.endswith(".deb"):
                continue
            if "=" not in tok:
                unpinned.append(tok)
        if unpinned:
            issues.append(("apt", unpinned))

    elif cmd == "apk" and "add" in rest:
        sub = rest[rest.index("add") + 1 :]
        unpinned = []
        skip_next = False
        for tok in sub:
            if skip_next:
                skip_next = False
                continue
            if tok in ("-t", "--virtual", "--repository", "-X"):
                skip_next = True
                continue
            if tok.startswith("-") or tok.endswith(".apk"):
                continue
            if "=" not in tok:
                unpinned.append(tok)
        if unpinned:
            issues.append(("apk", unpinned))

    return issues


def check_unpinned_dependencies(parsed: ParsedDockerfile) -> List[Finding]:
    """DF-005: Detect unpinned pip, npm, apt, or apk dependencies in RUN commands."""
    findings: List[Finding] = []

    for instr in parsed.instructions:
        if instr.instruction != "RUN":
            continue

        for segment in _SHELL_SPLIT_RE.split(instr.arguments):
            tokens = _tokenize_command(segment)
            for eco, pkgs in _find_unpinned_in_segment(tokens):
                pkg_preview = ", ".join(pkgs[:6]) + ("..." if len(pkgs) > 6 else "")
                findings.append(
                    _make_finding(
                        rule_id="DF-005",
                        title=f"Unpinned {eco} dependencies in RUN instruction",
                        severity="Medium",
                        location=f"{parsed.path}:{instr.line_number}",
                        evidence=f"{eco}: {pkg_preview}",
                        description=(
                            f"Installing {eco} package(s) without pinned versions ({pkg_preview}) "
                            "can introduce unexpected breaking changes or vulnerable versions across builds."
                        ),
                        remediation=f"Pin exact package versions (or use a lockfile) for {eco} installations.",
                        file_path=parsed.path,
                        line_number=instr.line_number,
                        confidence_score=0.90,
                    )
                )

    return findings


def check_insecure_install_commands(parsed: ParsedDockerfile) -> List[Finding]:
    """DF-006: Detect curl|sh pipes, disabled TLS/signature checks, HTTP downloads, and chmod 777."""
    findings: List[Finding] = []

    for instr in parsed.instructions:
        if instr.instruction != "RUN":
            continue

        cmd_text = instr.arguments
        location = f"{parsed.path}:{instr.line_number}"

        if _PIPE_TO_SHELL_RE.search(cmd_text):
            findings.append(
                _make_finding(
                    rule_id="DF-006",
                    title="Remote script piped directly to shell",
                    severity="Critical",
                    location=location,
                    evidence=instr.raw[:140],
                    description=(
                        "Piping a remote download directly into a shell executes unverified code "
                        "and is vulnerable to MitM or compromised upstream hosts."
                    ),
                    remediation="Download the script separately, verify its SHA256 checksum or signature, and then execute it.",
                    file_path=parsed.path,
                    line_number=instr.line_number,
                    confidence_score=0.95,
                )
            )

        for pattern, label in _INSECURE_TLS_PATTERNS:
            if pattern.search(cmd_text):
                findings.append(
                    _make_finding(
                        rule_id="DF-006",
                        title=f"Insecure installation flag: {label}",
                        severity="High",
                        location=location,
                        evidence=label,
                        description=(
                            f"Disabling TLS or package signature verification ({label}) exposes "
                            "image builds to man-in-the-middle tampering."
                        ),
                        remediation="Remove TLS/signature bypass flags and configure trusted CA certificates properly.",
                        file_path=parsed.path,
                        line_number=instr.line_number,
                        confidence_score=0.95,
                    )
                )

        http_match = _HTTP_DOWNLOAD_RE.search(cmd_text)
        if http_match:
            findings.append(
                _make_finding(
                    rule_id="DF-006",
                    title="Unencrypted HTTP download during build",
                    severity="Medium",
                    location=location,
                    evidence=http_match.group(1),
                    description=(
                        "Downloading build artifacts over plaintext `http://` allows tampering in transit."
                    ),
                    remediation="Use `https://` and verify the downloaded artifact's checksum.",
                    file_path=parsed.path,
                    line_number=instr.line_number,
                    confidence_score=0.90,
                )
            )

        if _CHMOD_777_RE.search(cmd_text):
            findings.append(
                _make_finding(
                    rule_id="DF-006",
                    title="Overly permissive world-writable chmod (777)",
                    severity="Medium",
                    location=location,
                    evidence=instr.raw[:140],
                    description=(
                        "Setting `chmod 777` grants read, write, and execute permissions to all users, "
                        "allowing any compromised process to tamper with files."
                    ),
                    remediation="Apply least-privilege file permissions (e.g., `chmod 755` or `chmod 644`) and proper ownership.",
                    file_path=parsed.path,
                    line_number=instr.line_number,
                    confidence_score=0.95,
                )
            )

    return findings
