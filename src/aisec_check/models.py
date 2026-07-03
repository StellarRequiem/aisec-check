"""Finding schema.

────────────────────────────────────────────────────────────────────────────────
PROVENANCE — VENDORED, defensive-only copy.

``FindingDraft`` below was COPIED from an internal, local-only research tool's
``models.py`` (the defensive finding schema its access-control scanner emits). That
tool is offense-firewalled with no public remote, so per the project's reuse rules
the clean defensive dataclass is vendored here with this note rather than imported
as a git dependency. The offensive/governance types from the source module
(authorization gates, disclosure drafts, etc.) were NOT copied — only the finding
record the scanner produces.
────────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FindingDraft:
    """A CANDIDATE finding (a lead), not a proven exploit. ``claimed`` = asserted
    values, ``evidence`` = the file:line + pattern the scanner independently
    matched, ``sources`` = cited provenance. Emitted read-only; a human confirms."""
    target: str
    program: str
    finding_class: str
    title: str
    claimed_severity: str
    text: str = ""
    claimed: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)
    sources: list = field(default_factory=list)
