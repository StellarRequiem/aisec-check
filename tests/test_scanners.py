"""Tests for the optional third-party-scanner normalization (reuses mcp-bench parsers).

Skips cleanly when mcp-bench is not installed — the native detectors do not need it.
"""
import pytest

from aisec_check import scanners

pytestmark = pytest.mark.skipif(not scanners.HAVE_MCPBENCH,
                                reason="mcp-bench (scanners extra) not installed")


def test_normalize_sarif_into_our_schema():
    sarif = {"runs": [{"results": [{
        "ruleId": "python.lang.security.audit",
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "app/server.py"},
            "region": {"startLine": 42}}}],
    }]}]}
    out = scanners.normalize_sarif(sarif, "case1", "semgrep")
    assert len(out) == 1
    f = out[0]
    # mcp-bench base fields present + our added fields
    assert f["scanner"] == "semgrep"
    assert f["case"] == "case1"
    assert f["file"] == "server.py"
    assert f["line"] == 42
    assert "severity" in f and "title" in f


def test_normalize_bandit():
    report = {"results": [{"test_id": "B301", "filename": "/x/app.py", "line_number": 7}]}
    out = scanners.normalize_bandit(report, "case1")
    assert out[0]["cls"] == "B301"
    assert out[0]["file"] == "app.py"
    assert out[0]["line"] == 7


def test_wilson_ci_reuse():
    lo, hi = scanners.wilson_ci(0, 3)
    assert lo == 0.0
    assert 0.5 < hi < 0.6  # 0/3 bounds the true rate to ~[0, 56%]
