"""Seal a finding set into an integrity-checked receipt, committing to a hash of the exact
scan inputs (repo target + normalized findings), and record it on an append-only
``AuditChain``. The unkeyed root detects corruption/reordering/truncation — it is NOT
tamper-evidence against a determined rewrite (that needs a key or an anchored chain head).

Reuses ``verity-core``'s canonical-JSON→sha256 ``entry_hash`` + ``AuditChain`` — we do
NOT roll our own crypto or fork the hash chain. This is the same sealing pattern
scorecheck/groundtruth use, so receipts cross-verify against the family.

HONEST THREAT MODEL (do not overstate): the receipt root is an UNKEYED hash, so
``verify_receipt`` catches CORRUPTION and naive edits but is NOT forgery-proof on its
own — anyone who controls the receipt file can change a field and recompute the root.
Real verification re-runs the scan and re-seals; standing integrity over time needs the
root anchored/published (or an HMAC key held by the verifier). Unkeyed = integrity, not
tamper-evidence against a determined rewrite.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from verity.audit import entry_hash, GENESIS, AuditChain


def canonical(obj) -> str:
    """Canonical JSON: sorted keys, ASCII, no spaces. No raw floats in sealed payloads
    (findings carry only ints/strings) so receipts are byte-reproducible."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _root(summary: dict, inputs_sha256: str) -> str:
    return entry_hash(seq=0, prev_hash=GENESIS, actor="aisec-check", event_type="findings",
                      event_data={**summary, "inputs_sha256": inputs_sha256})


def seal_findings(summary: dict, findings: list, target: str, receipt_path: str, ledger_path: str) -> str:
    """Write a sealed receipt + append the finding-set summary to an audit chain.

    ``summary`` = the float-free scorecard (counts by class/severity + worst severity).
    ``findings`` = the normalized ``{scanner,case,cls,file,line,...}`` records the scan
    committed to. Returns the receipt root."""
    inputs_sha256 = hashlib.sha256(
        (canonical({"target": target}) + "\n" + canonical(findings)).encode("utf-8")).hexdigest()
    root = _root(summary, inputs_sha256)
    AuditChain(ledger_path).append(
        "findings", {**summary, "target": target, "inputs_sha256": inputs_sha256, "root": root},
        actor="aisec-check")
    Path(receipt_path).write_text(
        canonical({"root": root, "target": target, "summary": summary,
                   "inputs_sha256": inputs_sha256}) + "\n", encoding="utf-8")
    return root


def verify_receipt(receipt_path: str) -> tuple[bool, str]:
    """Re-derive the receipt root from its own contents — catches CORRUPTION / naive edits,
    NOT a forger who recomputes the unkeyed root (see module docstring)."""
    r = json.loads(Path(receipt_path).read_text(encoding="utf-8"))
    recomputed = _root(r["summary"], r["inputs_sha256"])
    ok = recomputed == r["root"]
    return ok, (f"OK root={recomputed}" if ok else f"MISMATCH recomputed={recomputed} != receipt={r['root']}")


# Back-compat alias: `seal(...)` == `seal_findings(...)`. The public package API exposes
# `seal` as the SUBMODULE (aisec_check.seal), so callers use `seal.seal_findings(...)`.
seal = seal_findings
