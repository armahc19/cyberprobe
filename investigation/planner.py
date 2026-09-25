"""Capability-based investigation planning and lifecycle management."""
from dataclasses import dataclass
from .intent import UserIntent


PLAN_STATUSES = ("planned", "active", "paused", "completed", "cancelled")


@dataclass
class InvestigationPlan:
    goal: str
    phases: tuple[str, ...]
    status: str = "planned"
    current_index: int = 0
    completed: tuple[str, ...] = ()

    @property
    def current_phase(self) -> str | None:
        if self.status in {"completed", "cancelled"} or self.current_index >= len(self.phases):
            return None
        return self.phases[self.current_index]


class InvestigationPlanner:
    def create(self, intent: UserIntent) -> InvestigationPlan:
        phases = list({
            "web": ("web_service_detection", "technology_detection", "web_content_discovery", "vulnerability_detection"),
            "vulnerability": ("service_detection", "technology_detection", "vulnerability_detection"),
            "defensive": ("local_posture", "evidence_review", "correlation"),
            "reconnaissance": ("host_discovery", "port_scanning", "service_detection", "technology_detection"),
        }[intent.domain])
        if intent.depth == "quick":
            phases = phases[:2]
        elif intent.depth == "deep":
            phases.extend(("validation", "correlation", "retest"))
        if "no intrusive checks" in intent.constraints:
            phases = [phase for phase in phases if phase not in {"validation", "retest"}]
        return InvestigationPlan(intent.goal, tuple(phases))

    def start(self, plan: InvestigationPlan) -> InvestigationPlan:
        if plan.status == "planned":
            plan.status = "active"
        return plan

    def pause(self, plan: InvestigationPlan) -> InvestigationPlan:
        if plan.status not in {"active", "planned"}:
            raise ValueError(f"Cannot pause a {plan.status} plan.")
        plan.status = "paused"
        return plan

    def resume(self, plan: InvestigationPlan) -> InvestigationPlan:
        if plan.status != "paused":
            raise ValueError(f"Cannot resume a {plan.status} plan.")
        plan.status = "active"
        return plan

    def next_phase(self, plan: InvestigationPlan) -> str | None:
        if plan.status == "planned":
            self.start(plan)
        if plan.status != "active":
            return None
        return plan.current_phase

    def complete_phase(self, plan: InvestigationPlan, phase: str | None = None) -> str:
        if plan.status != "active":
            raise ValueError(f"Cannot complete a phase while plan is {plan.status}.")
        expected = plan.current_phase
        if expected is None or (phase is not None and phase != expected):
            raise ValueError(f"Expected phase '{expected}', received '{phase}'.")
        plan.completed = (*plan.completed, expected)
        plan.current_index += 1
        if plan.current_index >= len(plan.phases):
            plan.status = "completed"
        return expected

    def revise(self, plan: InvestigationPlan, phases: tuple[str, ...], goal: str | None = None) -> InvestigationPlan:
        if plan.status in {"completed", "cancelled"}:
            raise ValueError(f"Cannot revise a {plan.status} plan.")
        completed = tuple(phase for phase in plan.completed if phase in phases)
        plan.goal = goal or plan.goal
        plan.phases = tuple(phases)
        plan.completed = completed
        plan.current_index = len(completed)
        return plan

    def progress(self, plan: InvestigationPlan) -> dict:
        return {
            "status": plan.status,
            "current_phase": plan.current_phase,
            "completed": list(plan.completed),
            "remaining": list(plan.phases[plan.current_index:]),
            "total": len(plan.phases),
        }
