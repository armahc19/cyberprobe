"""Serializable state for one investigation."""
from dataclasses import dataclass, field


@dataclass
class InvestigationState:
    goal: str | None = None
    target: str | None = None
    target_type: str = "unknown"
    constraints: list[str] = field(default_factory=list)
    priority: str = "balanced"
    depth: str = "standard"
    plan: list[str] = field(default_factory=list)
    plan_status: str = "planned"
    current_phase: str | None = None
    completed_phases: list[str] = field(default_factory=list)
    discoveries: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)

    def update(self, result: dict) -> None:
        self.discoveries.extend(result.get("observations", []))
        self.findings.extend(result.get("findings", []))
