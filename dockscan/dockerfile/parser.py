"""Dockerfile parser supporting line continuations and multi-stage builds."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple


@dataclass(frozen=True)
class DockerfileInstruction:
    """A single logical Dockerfile instruction with its starting line number."""

    instruction: str  # Uppercase directive name, e.g. "FROM", "RUN", "ADD"
    arguments: str
    raw: str
    line_number: int
    stage_index: int


@dataclass
class BuildStage:
    """Represents one `FROM ...` stage in a Dockerfile."""

    index: int
    base_image: str
    alias: Optional[str]
    from_line: int
    instructions: List[DockerfileInstruction] = field(default_factory=list)


@dataclass
class ParsedDockerfile:
    """Structured representation of a parsed Dockerfile."""

    path: str
    stages: List[BuildStage] = field(default_factory=list)
    instructions: List[DockerfileInstruction] = field(default_factory=list)


def _split_from_arguments(arguments: str) -> Tuple[str, Optional[str]]:
    """Extract `(base_image, alias)` from `FROM [--platform=...] <image> [AS <name>]`."""
    tokens = arguments.split()
    filtered = [tok for tok in tokens if not tok.startswith("--")]
    if not filtered:
        return "", None

    base_image = filtered[0]
    alias: Optional[str] = None
    if len(filtered) >= 3 and filtered[1].upper() == "AS":
        alias = filtered[2]
    return base_image, alias


def parse_dockerfile_text(content: str, path: str = "Dockerfile") -> ParsedDockerfile:
    """Parse Dockerfile text into logical instructions and build stages."""
    logical_lines: List[Tuple[int, str]] = []
    buffer: List[str] = []
    start_line: Optional[int] = None

    for line_no, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()

        # Inside a continuation, Docker ignores comment lines without breaking it.
        if start_line is not None and stripped.startswith("#"):
            continue
        if start_line is None and (not stripped or stripped.startswith("#")):
            continue

        if start_line is None:
            start_line = line_no

        if stripped.endswith("\\"):
            part = stripped[:-1].rstrip()
            if part:
                buffer.append(part)
            continue

        buffer.append(stripped)
        logical_lines.append((start_line, " ".join(buffer).strip()))
        buffer = []
        start_line = None

    if buffer and start_line is not None:
        logical_lines.append((start_line, " ".join(buffer).strip()))

    stages: List[BuildStage] = []
    instructions: List[DockerfileInstruction] = []
    current_stage: Optional[BuildStage] = None

    for line_no, logical in logical_lines:
        parts = logical.split(None, 1)
        directive = parts[0].upper()
        arguments = parts[1].strip() if len(parts) > 1 else ""

        if directive == "FROM":
            base_image, alias = _split_from_arguments(arguments)
            current_stage = BuildStage(
                index=len(stages),
                base_image=base_image,
                alias=alias,
                from_line=line_no,
            )
            stages.append(current_stage)

        stage_idx = current_stage.index if current_stage is not None else -1
        instr = DockerfileInstruction(
            instruction=directive,
            arguments=arguments,
            raw=logical,
            line_number=line_no,
            stage_index=stage_idx,
        )
        instructions.append(instr)
        if current_stage is not None:
            current_stage.instructions.append(instr)

    return ParsedDockerfile(path=path, stages=stages, instructions=instructions)


def parse_dockerfile_file(path: Path) -> ParsedDockerfile:
    """Read and parse a Dockerfile from disk."""
    content = path.read_text(encoding="utf-8", errors="replace")
    return parse_dockerfile_text(content, path=str(path))
