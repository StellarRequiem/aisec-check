"""Tests for the core pipeline (scan/summarize/exit) and the verity-sealed receipt."""
import json
from pathlib import Path

import aisec_check.seal as seal_mod
from aisec_check import core, sarif

FIX = Path(__file__).parent / "fixtures"


def test_scan_vulnerable_file_has_findings():
    findings = core.scan_path(str(FIX / "vulnerable" / "deser_secrets.py"))
    assert findings, "expected findings in the vulnerable fixture"
    classes = {f["cls"] for f in findings}
    assert "unsafe-deserialization" in classes
    assert core.worst_severity(findings) in ("high", "critical")


def test_scan_safe_file_clean():
    findings = core.scan_path(str(FIX / "safe" / "deser_secrets.py"))
    assert findings == []
    assert core.exit_code(findings) == 0


def test_scan_safe_routes_clean():
    findings = core.scan_path(str(FIX / "safe" / "routes.py"))
    assert findings == []


def test_scan_vulnerable_routes_all_classes():
    findings = core.scan_path(str(FIX / "vulnerable" / "routes.py"))
    classes = {f["cls"] for f in findings}
    assert {"auth-bypass", "idor", "secret-leak", "ssrf"} <= classes


def test_findings_ranked_worst_first():
    findings = core.scan_path(str(FIX / "vulnerable" / "deser_secrets.py"))
    sevs = [core._SEV_ORDER[f["severity"]] for f in findings]
    assert sevs == sorted(sevs, reverse=True)


def test_dedup_removes_same_class_file_line():
    dup = [
        {"cls": "idor", "file": "a.py", "line": 3, "severity": "high", "title": "x"},
        {"cls": "idor", "file": "a.py", "line": 3, "severity": "high", "title": "x"},
    ]
    assert len(core._dedup(dup)) == 1


def test_summarize_is_float_free():
    findings = core.scan_path(str(FIX / "vulnerable" / "deser_secrets.py"))
    s = core.summarize(findings)
    # every value in the sealed summary must be int/str/dict-of-those — no floats
    def _no_float(o):
        if isinstance(o, float):
            return False
        if isinstance(o, dict):
            return all(_no_float(v) for v in o.values())
        if isinstance(o, list):
            return all(_no_float(v) for v in o)
        return True
    assert _no_float(s)
    assert s["total"] == len(findings)


def test_seal_and_verify_roundtrip(tmp_path):
    findings = core.scan_path(str(FIX / "vulnerable" / "deser_secrets.py"))
    summary = core.summarize(findings)
    receipt = tmp_path / "receipt.json"
    ledger = tmp_path / "ledger.jsonl"
    root = seal_mod.seal_findings(summary, findings, "fixture", str(receipt), str(ledger))
    assert root and len(root) == 64  # sha256 hex
    ok, msg = seal_mod.verify_receipt(str(receipt))
    assert ok, msg
    # ledger is an append-only audit chain and verifies
    from verity.audit import AuditChain
    chain_ok, _ = AuditChain(str(ledger)).verify()
    assert chain_ok


def test_seal_detects_tampering(tmp_path):
    findings = core.scan_path(str(FIX / "vulnerable" / "deser_secrets.py"))
    summary = core.summarize(findings)
    receipt = tmp_path / "receipt.json"
    seal_mod.seal_findings(summary, findings, "fixture", str(receipt), str(tmp_path / "l.jsonl"))
    r = json.loads(receipt.read_text())
    r["summary"]["total"] = 999  # tamper with a committed field
    receipt.write_text(json.dumps(r))
    ok, _ = seal_mod.verify_receipt(str(receipt))
    assert not ok, "tampered receipt must not re-derive"


def test_seal_receipt_is_canonical(tmp_path):
    findings = core.scan_path(str(FIX / "vulnerable" / "deser_secrets.py"))
    summary = core.summarize(findings)
    receipt = tmp_path / "receipt.json"
    root1 = seal_mod.seal_findings(summary, findings, "fixture", str(receipt), str(tmp_path / "l1.jsonl"))
    # re-sealing the identical inputs yields the identical root (byte-reproducible)
    receipt2 = tmp_path / "receipt2.json"
    root2 = seal_mod.seal_findings(summary, findings, "fixture", str(receipt2), str(tmp_path / "l2.jsonl"))
    assert root1 == root2


def test_sarif_shape():
    findings = core.scan_path(str(FIX / "vulnerable" / "deser_secrets.py"))
    doc = sarif.to_sarif(findings)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "aisec-check"
    assert len(doc["runs"][0]["results"]) == len(findings)
    for res in doc["runs"][0]["results"]:
        assert res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
