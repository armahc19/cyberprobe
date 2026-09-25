"""Cross-tool finding correlation and duplicate removal."""
from __future__ import annotations

import re
from collections import defaultdict
from urllib.parse import urlparse


def _clean(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _asset(value: object) -> str:
    text = str(value or "").strip().lower()
    parsed = urlparse(text)
    return parsed.netloc or parsed.path or text


class ResultCorrelator:
    """Merge only findings with the same stable identity and preserve provenance."""

    def fingerprint(self, finding: dict) -> tuple:
        identifier = finding.get("cve") or finding.get("template_id") or finding.get("template-id") or finding.get("id")
        asset = _asset(finding.get("affected_asset") or finding.get("host") or finding.get("matched-at"))
        title = _clean(finding.get("title") or finding.get("name") or "unknown finding")
        # Stable identifiers are stronger than titles; otherwise include the
        # asset so equal issues on different systems remain separate.
        return (str(identifier).lower(), asset) if identifier else (title, asset)

    def correlate(self, records: list[dict]) -> list[dict]:
        grouped: dict[tuple, dict] = {}
        source_sets: dict[tuple, set[str]] = defaultdict(set)
        for record in records:
            tool = record.get("tool") or record.get("agent") or "unknown"
            for raw in record.get("findings", []):
                finding = dict(raw)
                key = self.fingerprint(finding)
                if key not in grouped:
                    grouped[key] = {**finding, "sources": [], "evidence": list(finding.get("evidence", [])), "occurrences": 0}
                item = grouped[key]
                item["occurrences"] += 1
                source_sets[key].add(tool)
                for evidence in finding.get("evidence", []):
                    if evidence not in item["evidence"]:
                        item["evidence"].append(evidence)
                for field in ("severity", "impact", "remediation", "recommended_validation"):
                    if not item.get(field) and finding.get(field):
                        item[field] = finding[field]
        results = []
        for key, item in grouped.items():
            item["sources"] = sorted(source_sets[key])
            item["independent_sources"] = len(item["sources"])
            if item["independent_sources"] >= 2 and item.get("confidence") in {None, "low", "medium"}:
                item["confidence"] = "high"
            results.append(item)
        return results
