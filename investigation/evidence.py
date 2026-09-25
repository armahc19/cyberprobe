"""Evidence store for raw tool results and normalized findings."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from .evidence_model import EvidenceGraph


@dataclass
class EvidenceStore:
    records: list[dict] = field(default_factory=list)
    graph: EvidenceGraph = field(default_factory=EvidenceGraph)

    def add(self, *, agent: str, request: str, result: dict) -> dict:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": agent,
            "request": request[:2000],
            "tool": result.get("tool") or result.get("tool_type") or result.get("scan_type"),
            "command": result.get("command"),
            "target": result.get("target"),
            "raw_output": (result.get("stdout") or result.get("evidence") or "")[:16000],
            "findings": result.get("findings", []),
        }
        self.records.append(record)
        self.graph.ingest(result, source=record["tool"] or agent)
        return record
