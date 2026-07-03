"""aisec-check — a lexical/AST-first-cut CI linter for AI-app vuln classes.

Read-only, leads-only static analysis. Emits a SARIF report + a sealed (verity.audit)
receipt. See README for the exact rule list and the honest scope of what each detector
does (and does not) catch.
"""
from . import seal  # submodule (seal.seal / seal.verify_receipt / seal.canonical)
from .core import scan_path, summarize, worst_severity, exit_code
from .seal import seal_findings, verify_receipt, canonical

__all__ = ["scan_path", "summarize", "worst_severity", "exit_code",
           "seal", "seal_findings", "verify_receipt", "canonical"]
__version__ = "0.1.0"
