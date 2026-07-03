"""Emit findings as SARIF 2.1.0 (the format GitHub code-scanning and most CI ingest).

Pure: normalized findings → SARIF dict. The inverse (SARIF → normalized findings, for
bundled 3rd-party scanners) reuses ``mcpbench.parse_sarif`` — we do not re-implement SARIF
parsing here.
"""
from __future__ import annotations

# SARIF level per our severity.
_SEV_TO_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                 "low": "note", "none": "none"}


def to_sarif(findings: list, *, tool_name: str = "aisec-check", version: str = "0.1.0") -> dict:
    rules_seen: dict[str, dict] = {}
    results = []
    for f in findings:
        rid = f["cls"]
        rules_seen.setdefault(rid, {"id": rid, "name": rid,
                                    "shortDescription": {"text": rid}})
        results.append({
            "ruleId": rid,
            "level": _SEV_TO_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f["title"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": max(1, int(f["line"] or 1))},
                }
            }],
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": tool_name,
                "version": version,
                "informationUri": "https://example.invalid/aisec-check",
                "rules": list(rules_seen.values()),
            }},
            "results": results,
        }],
    }
