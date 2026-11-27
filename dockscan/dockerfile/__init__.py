"""Phase 6 static Dockerfile security analysis package."""

from dockscan.dockerfile.analyzer import (
    analyze_dockerfile_file,
    analyze_dockerfile_text,
    check_latest_tags,
    check_missing_healthcheck,
    check_non_root_user,
    check_unsafe_add,
)
from dockscan.dockerfile.parser import (
    BuildStage,
    DockerfileInstruction,
    ParsedDockerfile,
    parse_dockerfile_file,
    parse_dockerfile_text,
)

__all__ = [
    "BuildStage",
    "DockerfileInstruction",
    "ParsedDockerfile",
    "analyze_dockerfile_file",
    "analyze_dockerfile_text",
    "check_latest_tags",
    "check_missing_healthcheck",
    "check_non_root_user",
    "check_unsafe_add",
    "parse_dockerfile_file",
    "parse_dockerfile_text",
]
