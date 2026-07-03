"""Normalize OPTIONAL bundled third-party SAST scanner output into aisec-check's finding schema.

Third-party scanners (semgrep/bandit/dlint) are UNTRUSTED code and must run only inside the
disposable CI runner (see .github/workflows/scan.yml) — never on a developer host. This module
does NOT run them; it only NORMALIZES their already-produced output, reusing mcp-bench's pure
parsers (``parse_sarif``/``parse_bandit``/``parse_dlint``) so we do not re-implement SARIF/JSON
parsing. It also re-exports ``wilson_ci`` for honest small-N intervals in any self-benchmark.

mcp-bench is an OPTIONAL dependency (the ``scanners`` extra). If it is not installed, importing
this module still works; the normalizers raise a clear error only when actually called.
"""
from __future__ import annotations

try:  # optional dep — the native detectors need nothing from mcp-bench
    from mcpbench import parse_sarif as _parse_sarif
    from mcpbench import parse_bandit as _parse_bandit
    from mcpbench import parse_dlint as _parse_dlint
    from mcpbench import wilson_ci as _wilson_ci
    HAVE_MCPBENCH = True
except Exception:  # noqa: BLE001
    HAVE_MCPBENCH = False
    _parse_sarif = _parse_bandit = _parse_dlint = _wilson_ci = None


def _require():
    if not HAVE_MCPBENCH:
        raise RuntimeError(
            "mcp-bench is not installed — `pip install 'aisec-check[scanners]'` to normalize "
            "third-party scanner output (native AST detectors do not need it).")


# mcp-bench emits {scanner,case,cls,file,line}; we add severity/title to match aisec-check's schema.
def _enrich(records: list, default_severity: str = "medium") -> list:
    out = []
    for r in records:
        out.append({**r, "severity": r.get("severity", default_severity),
                    "title": r.get("title", f"{r.get('scanner', '?')}:{r.get('cls', '?')}")})
    return out


def normalize_sarif(sarif: dict, case_name: str, scanner: str) -> list:
    """Reuse mcpbench.parse_sarif → aisec-check findings (e.g. a bundled semgrep run in CI)."""
    _require()
    return _enrich(_parse_sarif(sarif, case_name, scanner))


def normalize_bandit(report: dict, case_name: str, scanner: str = "bandit") -> list:
    _require()
    return _enrich(_parse_bandit(report, case_name, scanner))


def normalize_dlint(output: str, case_name: str, scanner: str = "dlint") -> list:
    _require()
    return _enrich(_parse_dlint(output, case_name, scanner))


def wilson_ci(successes: int, total: int):
    """95% Wilson score interval (reused from mcp-bench) for honest small-N detection rates."""
    _require()
    return _wilson_ci(successes, total)
