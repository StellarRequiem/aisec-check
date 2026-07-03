"""New AST/regex rules beyond the vendored access-control scanner.

These are the NEW DELTA of this package: file-level detectors for vuln classes the
hunts codified but the route-scoped access-control scanner does not cover. Every rule
emits the SAME ``FindingDraft`` schema as ``acdiff`` so the CLI can merge them.

HONEST SCOPE: these are LEXICAL / AST heuristics, deterministic and read-only. They
match syntactic shapes (call names, argument kinds, keyword args), NOT data flow or
semantics. A match is a LEAD a human must confirm — false positives and false
negatives are expected. No semantic grounding is claimed.

Rules:
  R1  unsafe-deserialization  — ``pickle.load``/``pickle.loads``/``torch.load`` (no
      ``weights_only=True``) / ``yaml.load`` without a safe loader / ``dill.load``.
  R2  plaintext-secret-storage — a secret-shaped value written to a file opened in a
      text/binary write mode (``open(..., "w")`` fed a token/secret/password), or a
      dotfile/credentials path opened for write. Lexical proximity within the AST.
  R3  world-readable-secret    — a chmod / os.open granting world/group read/write
      (mode bits ``0o004``/``0o002``/``0o044``/``0o777`` etc.) applied to a
      secret-shaped path.

R1/R3 are AST-based; R2 is AST-based with a lexical secret-name test.
"""
from __future__ import annotations

import ast
from pathlib import Path

from .models import FindingDraft

# secret-shaped substrings reused across rules (superset of the vendored scanner's keys)
_SECRET_HINTS = ("secret", "api_key", "apikey", "token", "password", "passwd", "client_secret",
                 "private_key", "access_key", "credential", "auth_token", "session_token",
                 "bearer", ".pem", "id_rsa", "credentials")

# ── shared helpers ──────────────────────────────────────────────────────────────────────
def _name(node) -> str:
    if isinstance(node, ast.Attribute):
        return f"{_name(node.value)}.{node.attr}".lstrip(".")
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        return _name(node.func)
    return ""


def _looks_secret(text: str) -> bool:
    t = (text or "").lower()
    return any(h in t for h in _SECRET_HINTS)


def _draft(target, program, fc, title, sev, text, file, line, extra=None) -> FindingDraft:
    ev = {"file": file, "line": line, "pattern": fc, "detector": "aisec-rules"}
    if extra:
        ev.update(extra)
    return FindingDraft(
        target=target, program=program, finding_class=fc, title=title, claimed_severity=sev,
        text=f"{text} (LEAD — lexical/AST match at {file}:{line}; confirm by reading the code).",
        evidence=ev,
        sources=[{"id": f"aisec:{file}:{line}", "facts": ev, "text": f"{fc} candidate @ {file}:{line}"}])


# ── R1: unsafe deserialization ──────────────────────────────────────────────────────────
# (callable-leaf, safe-guard-kwarg, safe-loader-arg-names)
_DESER_UNSAFE = {
    "pickle.load", "pickle.loads", "cpickle.load", "cpickle.loads",
    "dill.load", "dill.loads", "_pickle.load", "_pickle.loads",
}
# yaml.load is unsafe UNLESS a safe loader is passed
_YAML_SAFE_LOADERS = ("SafeLoader", "CSafeLoader", "BaseLoader")


def _is_torch_load_unsafe(call: ast.Call, dotted: str) -> bool:
    if dotted not in ("torch.load",):
        return False
    # safe iff weights_only=True is present
    for kw in call.keywords:
        if kw.arg == "weights_only" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return False
    return True


def _is_yaml_load_unsafe(call: ast.Call, dotted: str) -> bool:
    if dotted not in ("yaml.load",):
        return False
    # safe iff a Loader= (or 2nd positional) names a safe loader
    def _loader_name(node) -> str:
        return _name(node).split(".")[-1]
    for kw in call.keywords:
        if kw.arg == "Loader" and _loader_name(kw.value) in _YAML_SAFE_LOADERS:
            return False
    if len(call.args) >= 2 and _loader_name(call.args[1]) in _YAML_SAFE_LOADERS:
        return False
    return True


def scan_unsafe_deser(tree: ast.AST, *, file: str, target: str, program: str) -> list:
    drafts = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _name(node.func)
        leaf_pair = ".".join(dotted.split(".")[-2:])  # e.g. "pickle.loads"; robust to aliased imports
        cls = None
        detail = ""
        if leaf_pair in _DESER_UNSAFE:
            cls, detail = "unsafe-deserialization", f"`{dotted}()` deserializes arbitrary objects (code execution on crafted input)"
        elif leaf_pair == "torch.load" and _is_torch_load_unsafe(node, "torch.load"):
            cls, detail = "unsafe-deserialization", "`torch.load()` without `weights_only=True` unpickles arbitrary objects"
        elif leaf_pair == "yaml.load" and _is_yaml_load_unsafe(node, "yaml.load"):
            cls, detail = "unsafe-deserialization", "`yaml.load()` without a SafeLoader constructs arbitrary Python objects"
        if cls:
            drafts.append(_draft(
                target, program, cls,
                f"Unsafe deserialization via {dotted}()",
                "high", detail, file, node.lineno, {"sink": dotted}))
    return drafts


# ── R2: plaintext secret written to a file ──────────────────────────────────────────────
_WRITE_MODES = ("w", "wb", "w+", "wb+", "a", "ab", "wt")


def _open_is_write(call: ast.Call) -> bool:
    """Is this an open(...) / Path.open(...) in a write mode?"""
    leaf = _name(call.func).split(".")[-1]
    if leaf != "open":
        return False
    # mode = 2nd positional or mode= kwarg; default 'r' (read) → not a write
    mode = None
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
        mode = call.args[1].value
    for kw in call.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            mode = kw.value.value
    return isinstance(mode, str) and mode in _WRITE_MODES


def _open_target_text(call: ast.Call) -> str:
    """A best-effort string describing the path argument (constant value or name)."""
    if call.args:
        a = call.args[0]
        if isinstance(a, ast.Constant) and isinstance(a.value, str):
            return a.value
        return _name(a)
    return ""


def scan_plaintext_secret(tree: ast.AST, *, file: str, target: str, program: str) -> list:
    """Flag an open(...,'w') whose path OR nearby assigned variable is secret-shaped.

    Heuristic: within each function/module scope, if a write-mode ``open`` targets a
    secret-shaped path, OR the same statement's ``with``/assignment binds a
    secret-shaped name, flag it. Lexical + AST, deterministic."""
    drafts = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _open_is_write(node):
            continue
        path_text = _open_target_text(node)
        if _looks_secret(path_text):
            drafts.append(_draft(
                target, program, "plaintext-secret-storage",
                f"Secret-shaped path opened for write: {path_text}",
                "medium",
                f"`open({path_text!r}, 'w')` writes to a secret-shaped path — check the value is encrypted, not stored in cleartext",
                file, node.lineno, {"path": path_text}))
    # second pass: `with open(...,'w') as f: f.write(<secret-named var>)` proximity
    for node in ast.walk(tree):
        if not isinstance(node, ast.With):
            continue
        writes_secret = False
        for item in node.items:
            ctx = item.context_expr
            if isinstance(ctx, ast.Call) and _open_is_write(ctx):
                # scan the body for a .write(<secret-shaped>) call
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call) and _name(sub.func).split(".")[-1] == "write":
                        for arg in sub.args:
                            if isinstance(arg, ast.Name) and _looks_secret(arg.id):
                                writes_secret = True
                            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and _looks_secret(arg.value):
                                writes_secret = True
                if writes_secret:
                    drafts.append(_draft(
                        target, program, "plaintext-secret-storage",
                        "Secret-shaped value written to an opened file in cleartext",
                        "medium",
                        "A `with open(..., 'w')` block writes a secret-shaped variable/literal — check it is not persisted in cleartext",
                        file, node.lineno, {"detector_note": "with-open-write-secret"}))
    return drafts


# ── R3: world/group-readable secret file ────────────────────────────────────────────────
def _is_world_readable_mode(node) -> bool:
    """True if the integer mode grants any 'other' (world) read/write/execute bit (0o007)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return bool(node.value & 0o007)
    return False


def scan_world_readable_secret(tree: ast.AST, *, file: str, target: str, program: str) -> list:
    """Flag os.chmod / Path.chmod granting world-read on a secret-shaped path."""
    drafts = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        leaf = _name(node.func).split(".")[-1]
        if leaf != "chmod":
            continue
        # os.chmod(path, mode) → path is arg0, mode arg1; Path.chmod(mode) → mode is arg0
        mode_arg = node.args[-1] if node.args else None
        path_text = ""
        if len(node.args) >= 2:
            a0 = node.args[0]
            path_text = a0.value if (isinstance(a0, ast.Constant) and isinstance(a0.value, str)) else _name(a0)
        else:
            # Path.chmod(mode): describe the receiver, e.g. token_path.chmod(...)
            path_text = _name(node.func)
        if mode_arg is not None and _is_world_readable_mode(mode_arg):
            secret_ctx = _looks_secret(path_text) or _looks_secret(_name(node.func))
            sev = "high" if secret_ctx else "low"
            title = (f"World-readable permissions on secret-shaped path {path_text}" if secret_ctx
                     else f"World-readable chmod ({oct(mode_arg.value)})")
            if secret_ctx:
                drafts.append(_draft(
                    target, program, "world-readable-secret",
                    title, sev,
                    f"`chmod({oct(mode_arg.value)})` grants other/group access to a secret-shaped path — restrict to 0o600",
                    file, node.lineno, {"mode": oct(mode_arg.value), "path": path_text}))
    return drafts


# ── module entry ────────────────────────────────────────────────────────────────────────
_RULE_FUNCS = (scan_unsafe_deser, scan_plaintext_secret, scan_world_readable_secret)


def scan_source(src: str, *, file: str, target: str, program: str = "") -> list:
    """Run all new rules over one source string. Pure; never raises on bad syntax."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    drafts = []
    for fn in _RULE_FUNCS:
        drafts.extend(fn(tree, file=file, target=target, program=program))
    return drafts


def to_drafts(repo_dir: str, *, target: str, program: str = "", max_files: int = 2000) -> list:
    root = Path(repo_dir)
    skip = {".git", "node_modules", "venv", ".venv", "site-packages", "dist", "build", "__pycache__"}
    drafts, seen = [], 0
    for p in sorted(root.rglob("*.py")):
        if any(part in skip for part in p.parts):
            continue
        seen += 1
        if seen > max_files:
            break
        try:
            src = p.read_text(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        drafts.extend(scan_source(src, file=str(p.relative_to(root)), target=target, program=program))
    return drafts
