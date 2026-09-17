"""Common, serializable security finding model shared by CyberProbe agents."""

from dataclasses import asdict, dataclass, field

SEVERITIES = ("informational", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high", "confirmed")


@dataclass
class Finding:
    title: str
    severity: str = "informational"
    confidence: str = "low"
    evidence: list[str] = field(default_factory=list)
    affected_asset: str | None = None
    impact: str = ""
    remediation: str = ""
    recommended_validation: str = ""
    source: str | None = None

    def __post_init__(self):
        if not self.title.strip():
            raise ValueError("A finding needs a title.")
        if self.severity not in SEVERITIES:
            raise ValueError(f"Severity must be one of: {', '.join(SEVERITIES)}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"Confidence must be one of: {', '.join(CONFIDENCES)}")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict):
        allowed = {field_name for field_name in cls.__dataclass_fields__}
        return cls(**{key: item for key, item in value.items() if key in allowed})


def finding_schema() -> dict:
    """Return the JSON schema agents should follow when emitting findings."""
    return {
        "type": "object",
        "required": ["title", "severity", "confidence", "evidence", "impact", "remediation", "recommended_validation"],
        "properties": {
            "title": {"type": "string"},
            "severity": {"type": "string", "enum": list(SEVERITIES)},
            "confidence": {"type": "string", "enum": list(CONFIDENCES)},
            "evidence": {"type": "array", "items": {"type": "string"}},
            "affected_asset": {"type": ["string", "null"]},
            "impact": {"type": "string"},
            "remediation": {"type": "string"},
            "recommended_validation": {"type": "string"},
            "source": {"type": ["string", "null"]},
        },
    }
