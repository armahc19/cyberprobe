"""Deterministic analyst hints passed to the conversational AI layer."""
from .state import InvestigationState


class AIAnalyst:
    def next_steps(self, state: InvestigationState) -> list[str]:
        remaining = [phase for phase in state.plan if phase not in state.completed_phases]
        return remaining[:3]
