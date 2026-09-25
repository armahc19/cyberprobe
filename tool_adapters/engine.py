"""Capability-oriented tool engine built on top of tool adapters."""
from __future__ import annotations

from dataclasses import dataclass
from .registry import ToolRegistry, ToolResult, default_registry


@dataclass(frozen=True)
class ToolPlan:
    capability: str
    candidates: tuple[str, ...]
    selected: str | None
    reason: str


class ToolEngine:
    """Select available adapters and provide capability fallbacks."""

    PREFERENCES = {
        "host_discovery": ("nmap", "arp-scan"),
        "port_scanning": ("rustscan", "masscan", "nmap"),
        "service_detection": ("nmap",),
        "technology_detection": ("whatweb", "httpx", "nuclei"),
        "web_service_detection": ("httpx",),
        "web_content_discovery": ("ffuf", "gobuster"),
        "vulnerability_detection": ("nuclei", "nikto", "nmap"),
    }

    def __init__(self, registry: ToolRegistry | None = None):
        self.registry = registry or default_registry()

    def plan(self, capability: str) -> ToolPlan:
        adapters = self.registry.find(capability)
        names = {adapter.spec.name for adapter in adapters}
        candidates = tuple(name for name in self.PREFERENCES.get(capability, tuple(names)) if name in names)
        available = {adapter.spec.name for adapter in adapters if adapter.available()}
        selected = next((name for name in candidates if name in available), None)
        reason = "selected first available preferred adapter" if selected else "no installed adapter supports this capability"
        return ToolPlan(capability, candidates, selected, reason)

    def capabilities(self) -> list[dict]:
        return self.registry.capabilities()

    def inventory(self) -> list[dict]:
        """Return installed/missing tools and non-destructive version probes."""
        return self.registry.inventory()

    def run(self, capability: str, inputs: dict, tool: str | None = None) -> dict:
        plan = self.plan(capability)
        selected = tool or plan.selected
        if not selected:
            return ToolResult("none", capability, inputs.get("target"), "", "unavailable", error=plan.reason).to_dict()
        if tool and tool not in plan.candidates:
            raise ValueError(f"{tool} does not provide '{capability}'.")
        return self.registry.run(selected, capability, inputs)
