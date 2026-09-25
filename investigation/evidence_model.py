"""Common evidence graph shared by tool adapters and agents."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256

@dataclass
class EvidenceEntity:
    kind: str
    key: str
    attributes: dict = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

@dataclass(frozen=True)
class Relationship:
    source: str
    relation: str
    target: str
    source_tool: str | None = None

class EvidenceGraph:
    KINDS = {"asset", "port", "service", "technology", "endpoint", "vulnerability", "finding"}

    def __init__(self):
        self.entities: dict[str, EvidenceEntity] = {}
        self.relationships: list[Relationship] = []

    def add(self, kind: str, key: str, *, source: str | None = None, **attributes) -> EvidenceEntity:
        if kind not in self.KINDS:
            raise ValueError(f"Unknown evidence kind: {kind}")
        entity = self.entities.setdefault(f"{kind}:{key}", EvidenceEntity(kind, key))
        entity.attributes.update({k: v for k, v in attributes.items() if v is not None})
        if source and source not in entity.sources:
            entity.sources.append(source)
        return entity

    def link(self, source: str, relation: str, target: str, source_tool: str | None = None) -> None:
        item = Relationship(source, relation, target, source_tool)
        if item not in self.relationships:
            self.relationships.append(item)

    def ingest(self, result: dict, source: str | None = None) -> None:
        for item in result.get("observations", []):
            asset = item.get("asset") or item.get("host") or item.get("url")
            if not asset:
                continue
            self.add("asset", asset, source=source, target=asset)
            if item.get("port"):
                key = f"{asset}:{item['port']}/{item.get('protocol', 'tcp')}"
                self.add("port", key, source=source, number=item["port"], protocol=item.get("protocol"), state=item.get("state"))
                self.link(f"asset:{asset}", "exposes", f"port:{key}", source)
            if item.get("service"):
                key = f"{asset}:{item.get('port', 'unknown')}:{item['service']}"
                self.add("service", key, source=source, name=item["service"], product=item.get("product"), version=item.get("version"))
                self.link(f"asset:{asset}", "runs", f"service:{key}", source)
            if item.get("url"):
                endpoint = item["url"]
                self.add("endpoint", endpoint, source=source, url=endpoint)
                self.link(f"asset:{asset}", "hosts", f"endpoint:{endpoint}", source)
        for finding in result.get("findings", []):
            title = finding.get("title", "unknown finding")
            key = sha256(f"{title}:{finding.get('affected_asset')}".encode()).hexdigest()[:16]
            self.add("vulnerability", key, source=source, title=title, severity=finding.get("severity"), evidence=finding.get("evidence", []), affected_asset=finding.get("affected_asset"))

    def to_dict(self) -> dict:
        return {"entities": [asdict(entity) for entity in self.entities.values()], "relationships": [asdict(link) for link in self.relationships]}
