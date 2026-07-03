"""aisec-check CLI.

    aisec-check scan <path> [--sarif out.sarif] [--receipt r.json] [--ledger l.jsonl] [--json]
    aisec-check verify --receipt r.json

`scan` exit code = worst severity found: 0 clean, 1 low, 2 medium, 3 high, 4 critical.
`verify` exit code = 0 if the receipt re-derives, else 1.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import core, sarif, seal


def _cmd_scan(a) -> int:
    findings = core.scan_path(a.path, target=a.target or "", program=a.program or "")
    summary = core.summarize(findings)

    if a.sarif:
        with open(a.sarif, "w", encoding="utf-8") as f:
            json.dump(sarif.to_sarif(findings, version="0.1.0"), f, indent=2)

    root = None
    if a.receipt:
        root = seal.seal_findings(summary, findings, a.target or a.path,
                                  receipt_path=a.receipt, ledger_path=a.ledger or (a.receipt + ".ledger.jsonl"))

    if a.json:
        json.dump({"summary": summary, "findings": findings, "receipt_root": root},
                  sys.stdout, indent=2)
        print()
    else:
        for f in findings:
            print(f"  [{f['severity']:>8}] {f['cls']:<26} {f['file']}:{f['line']}  {f['title']}")
        print(f"\n  {summary['total']} finding(s); worst={summary['worst_severity']}"
              + (f"; receipt_root={root[:16]}…" if root else ""))
        if summary["total"]:
            print("  NOTE: leads only — each is a candidate a human must confirm (lexical/AST, not semantic).")

    return core.exit_code(findings)


def _cmd_verify(a) -> int:
    ok, msg = seal.verify_receipt(a.receipt)
    print(("OK  " if ok else "FAIL ") + msg)
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="aisec-check",
                                 description="Lexical/AST first-cut linter for AI-app vuln classes (leads only).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a file or directory")
    s.add_argument("path")
    s.add_argument("--target", default="", help="label for the scanned target (default: basename)")
    s.add_argument("--program", default="")
    s.add_argument("--sarif", default="", help="write SARIF 2.1.0 to this path")
    s.add_argument("--receipt", default="", help="write a sealed receipt to this path")
    s.add_argument("--ledger", default="", help="audit-chain JSONL path (default: <receipt>.ledger.jsonl)")
    s.add_argument("--json", action="store_true", help="emit findings as JSON to stdout")
    s.set_defaults(func=_cmd_scan)

    v = sub.add_parser("verify", help="re-derive a sealed receipt's root")
    v.add_argument("--receipt", required=True)
    v.set_defaults(func=_cmd_verify)

    a = ap.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    raise SystemExit(main())
