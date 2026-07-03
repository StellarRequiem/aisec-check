"""Access-control differ (PURE AST; no subprocess, no network, no install).

────────────────────────────────────────────────────────────────────────────────
PROVENANCE — VENDORED, defensive-only copy.

This file was COPIED verbatim (defensive detector core only) from an internal,
local-only research tool's ``adapters/acdiff.py``. That tool is offense-firewalled
and has no public remote, so it cannot be a git dependency of this package; per the
project's reuse rules the two clean DEFENSIVE files (this scanner + its
``FindingDraft`` model) are vendored with this note instead. NO offensive code was
copied. This is a read-only, leads-only static analyzer: it parses source text and
emits CANDIDATE findings a human must confirm — it never runs the target and never
proves an exploit.
────────────────────────────────────────────────────────────────────────────────

Reads READ-ONLY source and flags four access-control asymmetry patterns:

  1. AUTH ASYMMETRY  — a route handler with NO auth dependency sitting beside siblings
     that HAVE one. finding_class=auth-bypass.
  2. IDOR / BOLA     — a handler takes a client-supplied id/user_id and queries by it
     with no visible owner binding. class=idor.
  3. SECRET LEAK     — a return / dict serialises a secret-shaped field
     (api_key/secret/token/password/client_secret) with no redaction. class=secret-leak.
  4. SSRF / PATH     — user-derived input flows into an HTTP client (requests/httpx/urllib)
     or a path sink (os.path.join/open/str.replace). class=ssrf / path-traversal.

It is a READ-ONLY analysis adapter — it parses source text, it does not run the target.
Leads only.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

from .models import FindingDraft

# ── pattern vocab ─────────────────────────────────────────────────────────────────────
_AUTH_HINTS = ("get_current_user", "current_user", "require_auth", "auth", "authenticate",
               "verify_token", "login_required", "jwt", "get_user", "authorize", "principal",
               "security", "bearer", "oauth")
_ID_PARAMS = ("id", "user_id", "uid", "account", "account_id", "owner", "owner_id", "tenant",
              "tenant_id", "org_id", "user")
_SECRET_KEYS = ("secret", "api_key", "apikey", "token", "password", "passwd", "client_secret",
                "private_key", "access_key", "credential", "auth_token", "session_token")
_HTTP_CALLS = ("get", "post", "put", "delete", "request", "urlopen", "urlretrieve", "fetch", "send")
_HTTP_MODS = ("requests", "httpx", "urllib", "aiohttp", "urllib3")
_PATH_SINKS = ("join", "open", "replace", "abspath", "realpath", "normpath")
_ROUTE_METHODS = ("get", "post", "put", "delete", "patch", "options", "route", "head")


def _name(node) -> str:
    """Best-effort dotted name for a Call/Attribute/Name node."""
    if isinstance(node, ast.Attribute):
        return f"{_name(node.value)}.{node.attr}".lstrip(".")
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        return _name(node.func)
    return ""


def _is_route(func: ast.AST) -> tuple | None:
    """If the function is a FastAPI/Flask/router route handler, return (method, path); else None."""
    for dec in getattr(func, "decorator_list", []):
        if not isinstance(dec, ast.Call):
            n = _name(dec)
            if n.split(".")[-1] in _ROUTE_METHODS and ("." in n):
                return (n.split(".")[-1], "")
            continue
        n = _name(dec.func)
        leaf = n.split(".")[-1]
        if leaf in _ROUTE_METHODS and "." in n:
            path = ""
            if dec.args and isinstance(dec.args[0], ast.Constant):
                path = str(dec.args[0].value)
            return (leaf, path)
    return None


def _decorator_has_auth(func: ast.AST) -> bool:
    """True if a route decorator declares auth via dependencies=[...] / a guard kwarg."""
    for dec in getattr(func, "decorator_list", []):
        if isinstance(dec, ast.Call):
            for kw in dec.keywords:
                if kw.arg in ("dependencies", "guards", "auth", "permissions") and _src_has_auth(kw.value):
                    return True
    return False


def _src_has_auth(node: ast.AST) -> bool:
    """Does any name/string under this node look auth-related?"""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and any(h in sub.id.lower() for h in _AUTH_HINTS):
            return True
        if isinstance(sub, ast.Attribute) and any(h in sub.attr.lower() for h in _AUTH_HINTS):
            return True
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and any(h in sub.value.lower() for h in _AUTH_HINTS):
            return True
    return False


def _arg_has_auth_dep(func: ast.AST) -> bool:
    """True if a function param defaults to Depends(<auth>) / Security(<auth>) — the FastAPI auth idiom."""
    args = getattr(func, "args", None)
    if not args:
        return False
    for default in list(args.defaults) + list(args.kw_defaults or []):
        if default is None:
            continue
        if isinstance(default, ast.Call):
            fn = _name(default.func).split(".")[-1].lower()
            if fn in ("depends", "security") and _src_has_auth(default):
                return True
    for a in list(args.args) + list(args.kwonlyargs):
        if any(h in a.arg.lower() for h in ("current_user", "principal", "auth_user")):
            return True
    return False


def _has_auth(func: ast.AST) -> bool:
    return _arg_has_auth_dep(func) or _decorator_has_auth(func)


def _id_params(func: ast.AST) -> list:
    args = getattr(func, "args", None)
    if not args:
        return []
    names = [a.arg for a in list(args.args) + list(args.kwonlyargs)]
    return [n for n in names if n.lower() in _ID_PARAMS or n.lower().endswith("_id")]


def _returns_secret(func: ast.AST) -> str:
    """A secret-shaped key referenced in a dict/return inside the handler (heuristic leak signal)."""
    for sub in ast.walk(func):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            if sub.value.lower() in _SECRET_KEYS:
                return sub.value
        if isinstance(sub, ast.Attribute) and sub.attr.lower() in _SECRET_KEYS:
            return sub.attr
    return ""


def _sinks(func: ast.AST) -> list:
    """HTTP-client + path sinks called with a NON-constant (likely user-derived) argument."""
    hits = []
    for sub in ast.walk(func):
        if not isinstance(sub, ast.Call):
            continue
        dotted = _name(sub.func)
        leaf = dotted.split(".")[-1].lower()
        root = dotted.split(".")[0].lower()
        nonconst = any(not isinstance(a, ast.Constant) for a in sub.args)
        if leaf in _HTTP_CALLS and (root in _HTTP_MODS or "client" in root or "session" in root) and nonconst:
            hits.append(("ssrf", dotted))
        elif leaf in _PATH_SINKS and nonconst and ("path" in dotted.lower() or leaf in ("open", "replace")):
            hits.append(("path-traversal", dotted))
    return hits


def _draft(target, program, fc, title, sev, text, file, line, extra=None) -> FindingDraft:
    ev = {"file": file, "line": line, "pattern": fc, "detector": "acdiff"}
    if extra:
        ev.update(extra)
    return FindingDraft(
        target=target, program=program, finding_class=fc, title=title, claimed_severity=sev,
        text=f"{text} (LEAD — acdiff static match at {file}:{line}; confirm by reading the code + a local PoC).",
        evidence=ev,
        sources=[{"id": f"acdiff:{file}:{line}", "facts": ev, "text": f"acdiff {fc} candidate @ {file}:{line}"}])


def scan_source(src: str, *, file: str, target: str, program: str = "") -> list:
    """Parse one Python source string and emit FindingDraft leads. Pure; never raises on bad syntax."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    routes = [(f, _is_route(f)) for f in funcs]
    routes = [(f, r) for f, r in routes if r]
    gated = [f for f, r in routes if _has_auth(f)]
    ungated = [f for f, r in routes if not _has_auth(f)]
    drafts = []
    # 1. AUTH ASYMMETRY — only meaningful when some siblings ARE gated (proves intent)
    if gated and ungated:
        for f in ungated:
            method, path = next(r for ff, r in routes if ff is f)
            drafts.append(_draft(
                target, program, "auth-bypass",
                f"Ungated route {method.upper()} {path or f.name} beside auth-gated siblings",
                "high",
                f"Handler `{f.name}` ({method.upper()} {path}) has no auth dependency while {len(gated)} sibling route(s) in this file do — the access-control asymmetry pattern",
                file, f.lineno, {"method": method, "path": path, "gated_siblings": len(gated)}))
    # 2/3/4 — per route handler
    for f, (method, path) in routes:
        ids = _id_params(f)
        if ids and not _has_auth(f):
            drafts.append(_draft(
                target, program, "idor",
                f"Possible IDOR: {method.upper()} {path or f.name} takes client id `{','.join(ids)}` without auth",
                "high",
                f"Handler `{f.name}` accepts client-supplied {ids} and is ungated — check for an owner/user_id binding before the DB access (the BOLA pattern)",
                file, f.lineno, {"id_params": ids, "method": method}))
        sk = _returns_secret(f)
        if sk:
            drafts.append(_draft(
                target, program, "secret-leak",
                f"Possible secret exposure ({sk}) in {method.upper()} {path or f.name}",
                "high",
                f"Handler `{f.name}` references secret-shaped field `{sk}` in its body/return — check it is not serialised to the caller in cleartext",
                file, f.lineno, {"secret_field": sk}))
        for cls, sink in _sinks(f):
            drafts.append(_draft(
                target, program, cls,
                f"Possible {cls.upper()} via {sink}() in {method.upper()} {path or f.name}",
                "high",
                f"Handler `{f.name}` calls `{sink}()` with non-constant input — check for user-controlled URL/path",
                file, f.lineno, {"sink": sink}))
    return drafts


def to_drafts(repo_dir: str, *, target: str, program: str = "", max_files: int = 2000) -> list:
    """Walk a cloned repo dir READ-ONLY, scanning .py files for the four access-control patterns.
    Skips vendored/test/build dirs. Pure (file reads only). Leads, not proofs."""
    root = Path(repo_dir)
    skip = {".git", "node_modules", "venv", ".venv", "site-packages", "dist", "build", "__pycache__",
            "tests", "test", "examples", "docs"}
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


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="acdiff — read-only access-control lead scanner (leads, not exploits)")
    ap.add_argument("repo_dir")
    ap.add_argument("--target", required=True)
    ap.add_argument("--program", default="")
    a = ap.parse_args()
    ds = to_drafts(a.repo_dir, target=a.target, program=a.program)
    for d in ds:
        print(json.dumps({"class": d.finding_class, "title": d.title, "file": d.evidence.get("file"),
                          "line": d.evidence.get("line")}, separators=(",", ":")))
    print(f"# acdiff: {len(ds)} leads (read-only static; confirm each by reading code + a local PoC)")
