#!/usr/bin/env python3
"""Aggregate raw aisec-check corpus findings into per-rule + overall count tables.

This is a PURE, host-safe reducer. It reads only the JSON result files that
``corpus-scan.yml`` produced (``findings/<slug>.json``, each the stdout of
``aisec-check scan --json``) and folds them into counts. It NEVER clones, runs,
imports, or otherwise executes any scanned target — it only sums integers out of
already-collected JSON. Because it is pure, ``aggregate_findings`` is unit-tested
on fixtures with no scanner and no network.

Precision is deliberately NOT computed here. Every aisec-check finding is a LEAD;
true-positive rate is only known after human adjudication (the next phase). This
step fixes the denominators — per-rule and overall finding counts, plus how many
repos produced findings / errored — so adjudication has a stable frame.

Each per-repo JSON has the shape emitted by aisec_check.cli._cmd_scan --json:

    {"summary": {"total": int,
                 "by_class": {rule: count, ...},
                 "by_severity": {sev: count, ...},
                 "worst_severity": str},
     "findings": [{"cls": str, "severity": str, "file": str,
                   "line": int, "title": str}, ...],
     "receipt_root": str | null}

Error stubs (clone failures) are written as ``<slug>.error.json`` = {"error": ...}
and are counted separately, never as findings.

Usage:
    python validation/aggregate.py <findings_dir> [--out agg.json] [--md agg.md]
"""
from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any, Iterable


# Fixed rule universe (the classes aisec-check can emit) so the table has stable
# rows even for rules that fired zero times across the corpus. Kept in sync with
# aisec_check.rules; an unknown class still gets counted (added dynamically).
KNOWN_RULES = (
    "auth-bypass",
    "idor",
    "secret-leak",
    "ssrf",
    "path-traversal",
    "unsafe-deserialization",
    "plaintext-secret-storage",
    "world-readable-secret",
    "ssrf-url-fetch",
    "hardcoded-secret",
    "template-injection",
    "command-injection",
)

SEVERITIES = ("critical", "high", "medium", "low", "info")


def _iter_result_records(results: Iterable[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    """Yield only successful scan records (those with a 'findings' list),
    skipping error stubs. Pure — operates on already-parsed dicts."""
    for rec in results:
        if isinstance(rec, dict) and "findings" in rec:
            yield rec


def aggregate_findings(
    per_repo: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Pure reducer: map of {slug -> parsed JSON} -> aggregate counts.

    Returns per-rule counts, per-severity counts, overall totals, and per-repo
    totals. Does NOT read the filesystem or run anything — feed it a dict, get a
    dict. This is the unit under test.
    """
    by_rule: dict[str, int] = {r: 0 for r in KNOWN_RULES}
    by_severity: dict[str, int] = {s: 0 for s in SEVERITIES}
    per_repo_total: dict[str, int] = {}
    repos_with_findings = 0
    repos_clean = 0
    repos_errored = 0
    total_findings = 0

    for slug, rec in sorted(per_repo.items()):
        if not isinstance(rec, dict) or "findings" not in rec:
            # error stub / clone failure
            repos_errored += 1
            per_repo_total[slug] = 0
            continue

        findings = rec.get("findings") or []
        per_repo_total[slug] = len(findings)
        total_findings += len(findings)
        if findings:
            repos_with_findings += 1
        else:
            repos_clean += 1

        for f in findings:
            cls = f.get("cls", "<unknown>")
            sev = f.get("severity", "<unknown>")
            by_rule[cls] = by_rule.get(cls, 0) + 1
            by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "corpus_size": len(per_repo),
        "repos_scanned_ok": repos_with_findings + repos_clean,
        "repos_with_findings": repos_with_findings,
        "repos_clean": repos_clean,
        "repos_errored": repos_errored,
        "total_findings": total_findings,
        "by_rule": dict(sorted(by_rule.items())),
        "by_severity": {s: by_severity[s] for s in SEVERITIES if s in by_severity},
        "per_repo_total": dict(sorted(per_repo_total.items())),
        # Precision is intentionally absent — see module docstring.
        "note": "raw lead counts; precision computed after human adjudication (next phase)",
    }


def load_results(findings_dir: str | pathlib.Path) -> dict[str, dict[str, Any]]:
    """Read every ``*.json`` result in ``findings_dir`` into {slug -> parsed}.

    This is the only IO in the module, and it is read-only JSON parsing of files
    THIS harness produced — not target code. Malformed JSON is recorded as an
    error stub rather than crashing the aggregation.
    """
    d = pathlib.Path(findings_dir)
    out: dict[str, dict[str, Any]] = {}
    for path in sorted(d.glob("*.json")):
        name = path.name
        if name.startswith("_"):
            continue  # skip our own _aggregate.json outputs
        # slug: strip .json and the .receipt/.error qualifiers
        slug = name[: -len(".json")]
        is_error = slug.endswith(".error")
        if slug.endswith(".receipt"):
            continue  # receipts aren't findings records
        slug = slug[: -len(".error")] if is_error else slug
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as e:
            rec = {"error": f"unreadable: {e}"}
        # If a repo has both a normal and an error file, the normal one wins.
        if slug in out and "findings" in out[slug]:
            continue
        out[slug] = rec
    return out


def render_markdown(agg: dict[str, Any]) -> str:
    """Render the aggregate dict as a Markdown report (per-rule + overall)."""
    lines: list[str] = []
    lines.append("# aisec-check corpus scan — raw finding counts\n")
    lines.append(f"> {agg['note']}\n")
    lines.append("## Overall\n")
    lines.append("| metric | value |")
    lines.append("|---|---|")
    lines.append(f"| corpus size (repos) | {agg['corpus_size']} |")
    lines.append(f"| scanned OK | {agg['repos_scanned_ok']} |")
    lines.append(f"| repos with >=1 finding | {agg['repos_with_findings']} |")
    lines.append(f"| repos clean | {agg['repos_clean']} |")
    lines.append(f"| repos errored (clone/parse) | {agg['repos_errored']} |")
    lines.append(f"| total findings (leads) | {agg['total_findings']} |")
    lines.append("")

    lines.append("## Findings per rule\n")
    lines.append("| rule | findings |")
    lines.append("|---|---|")
    for rule, n in agg["by_rule"].items():
        lines.append(f"| {rule} | {n} |")
    lines.append("")

    lines.append("## Findings per severity\n")
    lines.append("| severity | findings |")
    lines.append("|---|---|")
    for sev, n in agg["by_severity"].items():
        lines.append(f"| {sev} | {n} |")
    lines.append("")

    lines.append("## Findings per repo\n")
    lines.append("| repo | findings |")
    lines.append("|---|---|")
    for slug, n in sorted(agg["per_repo_total"].items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"| {slug} | {n} |")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Aggregate aisec-check corpus findings (pure count reducer).")
    ap.add_argument("findings_dir", help="directory of per-repo <slug>.json result files")
    ap.add_argument("--out", default="", help="write the aggregate JSON here")
    ap.add_argument("--md", default="", help="write the Markdown report here")
    a = ap.parse_args(argv)

    results = load_results(a.findings_dir)
    agg = aggregate_findings(results)

    if a.out:
        pathlib.Path(a.out).write_text(json.dumps(agg, indent=2), encoding="utf-8")
    md = render_markdown(agg)
    if a.md:
        pathlib.Path(a.md).write_text(md, encoding="utf-8")
    if not a.out and not a.md:
        print(json.dumps(agg, indent=2))
    else:
        print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
