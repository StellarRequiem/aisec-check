"""Core scan pipeline: fan out the detectors → normalize to one finding schema → merge/dedup
→ rank → summarize.

Normalized finding schema (shared with mcp-bench so scoring/parsing is reused):
    {"scanner", "case", "cls", "file", "line", "severity", "title"}

Detectors:
  * vendored access-control scanner (``acdiff``) — auth-bypass / idor / secret-leak / ssrf / path-traversal
  * new rules (``rules``) — unsafe-deserialization / plaintext-secret-storage / world-readable-secret
  * optional bundled 3rd-party SARIF scanners, normalized via ``mcpbench.parse_sarif`` (import; only
    invoked in the disposable CI runner, never on a host — see .github/workflows/scan.yml)
"""
from __future__ import annotations

from pathlib import Path

from . import acdiff, rules

# Severity ordering for worst-of and exit codes.
_SEV_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Default per-class severity (a draft may override via claimed_severity).
_CLASS_SEV = {
    "auth-bypass": "high",
    "idor": "high",
    "secret-leak": "high",
    "ssrf": "high",
    "path-traversal": "high",
    "unsafe-deserialization": "high",
    "plaintext-secret-storage": "medium",
    "world-readable-secret": "high",
}


def _normalize(draft, case: str) -> dict:
    """FindingDraft → the shared normalized finding dict."""
    ev = draft.evidence or {}
    sev = draft.claimed_severity or _CLASS_SEV.get(draft.finding_class, "medium")
    return {
        "scanner": ev.get("detector", "aisec-check"),
        "case": case,
        "cls": draft.finding_class,
        "file": ev.get("file", ""),
        "line": int(ev.get("line", 0) or 0),
        "severity": sev,
        "title": draft.title,
    }


def _dedup(findings: list) -> list:
    """Drop exact duplicates on (cls, file, line). Two detectors can land the same lead."""
    seen, out = set(), []
    for f in findings:
        key = (f["cls"], f["file"], f["line"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _rank(findings: list) -> list:
    """Sort worst-first: severity desc, then file, then line."""
    return sorted(findings, key=lambda f: (-_SEV_ORDER.get(f["severity"], 0), f["file"], f["line"]))


def worst_severity(findings: list) -> str:
    if not findings:
        return "none"
    return max((f["severity"] for f in findings), key=lambda s: _SEV_ORDER.get(s, 0))


def summarize(findings: list) -> dict:
    """Float-free scorecard for sealing: counts by class + by severity + worst severity.
    Integers/strings only so the sealed receipt is byte-reproducible."""
    by_class: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    for f in findings:
        by_class[f["cls"]] = by_class.get(f["cls"], 0) + 1
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return {
        "total": len(findings),
        "by_class": dict(sorted(by_class.items())),
        "by_severity": dict(sorted(by_sev.items())),
        "worst_severity": worst_severity(findings),
    }


def scan_path(path: str, *, target: str = "", program: str = "") -> list:
    """Run both native detector groups over a file or directory. Read-only. Returns
    ranked, deduped normalized findings. Does NOT run any 3rd-party scanner (those run
    only in the disposable CI runner)."""
    target = target or Path(path).name
    p = Path(path)
    raw = []
    if p.is_file() and p.suffix == ".py":
        src = p.read_text(encoding="utf-8", errors="replace")
        rel = p.name
        raw += acdiff.scan_source(src, file=rel, target=target, program=program)
        raw += rules.scan_source(src, file=rel, target=target, program=program)
    else:
        raw += acdiff.to_drafts(str(p), target=target, program=program)
        raw += rules.to_drafts(str(p), target=target, program=program)
    findings = [_normalize(d, case=target) for d in raw]
    return _rank(_dedup(findings))


def exit_code(findings: list) -> int:
    """Worst-severity → process exit code. 0 = clean, else 1..4 (low..critical)."""
    return _SEV_ORDER.get(worst_severity(findings), 0)
