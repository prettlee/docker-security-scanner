"""Data models for parsed Docker metadata and security findings."""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Capabilities:
    """Linux capabilities configured on a target (typically present on containers)."""

    add: List[str] = field(default_factory=list)
    drop: List[str] = field(default_factory=list)


@dataclass
class ImageMetadata:
    """Subset of Docker image/container metadata extracted from `docker inspect`."""

    target: str
    user: str
    exposed_ports: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    entrypoint: List[str] = field(default_factory=list)
    capabilities: Capabilities = field(default_factory=Capabilities)


@dataclass
class Finding:
    """Represents a single security issue discovered during a scan."""

    rule_id: str
    severity: str
    title: str
    description: str
    remediation: str
    evidence: Optional[str] = None


@dataclass
class ScanResult:
    """Complete scan output combining extracted metadata and findings."""

    metadata: ImageMetadata
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the scan result into plain Python dicts/lists for JSON output."""
        return asdict(self)
