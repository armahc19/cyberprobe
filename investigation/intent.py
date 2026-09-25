"""Structured intent extraction used before model planning."""
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class UserIntent:
    goal: str
    domain: str
    target: str | None = None
    target_type: str = "unknown"
    constraints: tuple[str, ...] = ()
    priority: str = "balanced"
    depth: str = "standard"
    output_style: str = "explained"


class IntentEngine:
    def understand(self, request: str, target: str | None = None) -> UserIntent:
        request = (request or "").strip()
        text = request.lower()
        if any(word in text for word in ("web", "website", "http", "api")):
            domain = "web"
        elif any(word in text for word in ("vulnerability", "cve", "weakness")):
            domain = "vulnerability"
        elif any(word in text for word in ("log", "incident", "suspicious", "forensic")):
            domain = "defensive"
        else:
            domain = "reconnaissance"
        if any(word in text for word in ("quick", "fast", "brief", "rapid")):
            depth = "quick"
        elif any(word in text for word in ("deep", "thorough", "full", "complete", "comprehensive")):
            depth = "deep"
        else:
            depth = "standard"

        if target and re.match(r"https?://", target, re.I):
            target_type = "web_url"
        elif any(word in text for word in ("website", "web app", "web server", "api")):
            target_type = "web_application"
        elif any(word in text for word in ("file", "disk", "memory", "image")):
            target_type = "artifact"
        elif any(word in text for word in ("local", "linux", "host", "server", "machine")):
            target_type = "host"
        elif target:
            target_type = "network_target"
        else:
            target_type = "unknown"

        constraints = []
        constraint_terms = {
            "no intrusive checks": ("non-intrusive", "non intrusive", "passive only", "read-only"),
            "no exploitation": ("no exploit", "without exploitation", "skip exploitation"),
            "explain steps": ("explain", "teach me", "beginner", "learning"),
            "avoid changes": ("do not modify", "don't modify", "no changes"),
        }
        for label, terms in constraint_terms.items():
            if any(term in text for term in terms):
                constraints.append(label)

        if any(word in text for word in ("urgent", "critical", "asap", "immediately")):
            priority = "urgent"
        elif any(word in text for word in ("coverage", "thorough", "complete")):
            priority = "coverage"
        elif any(word in text for word in ("quick", "fast", "speed")):
            priority = "speed"
        else:
            priority = "balanced"

        output_style = "technical" if any(word in text for word in ("technical", "raw output", "commands", "expert")) else "explained"
        return UserIntent(request, domain, target, target_type, tuple(constraints), priority, depth, output_style)
