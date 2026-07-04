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
  R4  ssrf-url-fetch           — ``requests``/``httpx``/``aiohttp`` ``.get``/``.post``/...
      or ``urllib.request.urlopen`` / bare ``urlopen`` where the URL is a NON-literal
      (variable / f-string / param) — a server-side fetch of a caller/model-controlled
      URL with no in-call literal allowlist.
  R5  hardcoded-secret         — an assignment (or secret-named kwarg) whose target is
      secret-shaped AND whose value is a secret-SHAPED string literal
      (``sk-…`` / ``AKIA…`` / long hex / long base64 / bearer-like token).
  R6  template-injection       — ``jinja2.Environment(autoescape=False)`` (XSS lead) OR
      ``Template(<non-literal>)`` / ``env.from_string(<non-literal>)`` /
      ``Template(...).render(...)`` where the template text is caller-controlled — an
      SSTI lead.
  R7  command-injection        — ``subprocess.*(..., shell=True)`` with a non-literal
      command, or ``os.system`` / ``os.popen`` with a non-literal argument — a shell
      metacharacter-injection lead.

R1/R3/R4/R6/R7 are AST-based; R2/R5 are AST-based with a lexical secret-name/shape test.
"""
from __future__ import annotations

import ast
import re
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


# ── controllability analysis (the precision core) ────────────────────────────────────────
# The dominant false-positive across every "non-literal → flag" rule was treating ANY
# variable as attacker-controlled. In real infra the argument is almost always a
# module-level constant, a config value, a literal-built string, or a wrapped Request
# object around a literal URL. These helpers answer the question the old rules skipped:
# *is this value plausibly derived from external / request / caller input?* Only then is it
# a lead. This is still lexical/AST (no real dataflow) — it under-claims by design.

# names that, as request-object receivers, signal request/caller-controlled input
_REQUEST_HINTS = ("request", "req", "flask.request", "self.request", "event", "payload",
                  "body", "params", "query", "form", "args", "json", "input", "user_input",
                  "message", "msg", "prompt", "untrusted", "external")
# safe module leaves whose calls produce a literal/config-derived value (env, config, settings)
_SAFE_SOURCE_LEAVES = ("getenv", "environ", "get", "config", "settings", "getconfig")


def _is_const_str_expr(node) -> bool:
    """True if this expression evaluates to a string built ONLY from literals / joined
    literals (no Name/param/call). e.g. 'a' , 'a' + 'b', f'{PREFIX_LITERAL}...' with no names."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.JoinedStr):  # f-string
        return all(
            isinstance(v, ast.Constant) or (isinstance(v, ast.FormattedValue) and _is_const_str_expr(v.value))
            for v in node.values
        )
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_const_str_expr(node.left) and _is_const_str_expr(node.right)
    return False


class _Scope:
    """Per-function view: which names are parameters (controllable), and which local names are
    bound to a value we can prove is NOT external (a literal, a module-const, a Request-wrapping
    of a safe URL). Module-level constants are also collected so a config URL is treated safe."""

    def __init__(self, module: ast.AST, func: ast.AST | None):
        self.params: set[str] = set()
        # names bound to a provably-safe (literal / const / env / config) value in this scope
        self.safe_names: set[str] = set()
        # names bound to Request(<safe-url>) — the wrapped-literal-Request pattern
        self.safe_request_names: set[str] = set()

        # module-level constants: ALL_CAPS or assigned a literal / env / config expr → safe source
        self.module_consts: set[str] = set()
        for n in module.body if isinstance(module, ast.Module) else []:
            if isinstance(n, (ast.Assign, ast.AnnAssign)):
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                val = n.value
                for t in targets:
                    nm = _name(t)
                    if not nm:
                        continue
                    if nm.isupper() or (val is not None and self._safe_value(val, module_pass=True)):
                        self.module_consts.add(nm)

        if func is not None:
            a = getattr(func, "args", None)
            if a:
                for arg in list(a.args) + list(a.kwonlyargs) + list(a.posonlyargs or []):
                    self.params.add(arg.arg)
                if a.vararg:
                    self.params.add(a.vararg.arg)
                if a.kwarg:
                    self.params.add(a.kwarg.arg)
            # walk the function body IN ORDER, tracking local safe bindings
            for stmt in ast.walk(func):
                if isinstance(stmt, ast.Assign):
                    for t in stmt.targets:
                        nm = _name(t)
                        if not nm:
                            continue
                        if self._is_request_of_safe_url(stmt.value):
                            self.safe_request_names.add(nm)
                        elif self._safe_value(stmt.value):
                            self.safe_names.add(nm)
                # `for x in <module-const/config>:` — the loop var is config-derived, not external.
                # e.g. `for name, url in NEWS_FEEDS.items():` iterates a module-level constant dict,
                # so `url` is a config value, NOT attacker input (a dominant SSRF false positive).
                elif isinstance(stmt, ast.For) and self._iterates_safe(stmt.iter):
                    for nm in self._bound_names(stmt.target):
                        self.safe_names.add(nm)

    def _safe_value(self, node, module_pass: bool = False) -> bool:
        """Is this RHS a value we can treat as non-external? Literals, module-consts, env/config
        reads, and simple ops over those. Conservative: unknown calls/names are NOT safe."""
        if node is None:
            return False
        if _is_const_str_expr(node):
            return True
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.Name):
            if module_pass:
                return node.id.isupper()
            return node.id in self.module_consts or node.id in self.safe_names
        if isinstance(node, ast.Attribute):
            # os.environ / settings.X / config.X style — treated as config, not request input
            leaf = node.attr.lower()
            root = _name(node).split(".")[0].lower()
            return root in ("os", "settings", "config", "cfg", "env") or leaf in _SAFE_SOURCE_LEAVES
        if isinstance(node, ast.Call):
            leaf = _name(node.func).split(".")[-1].lower()
            return leaf in _SAFE_SOURCE_LEAVES
        if isinstance(node, ast.JoinedStr):
            # f-string safe iff every interpolated piece is safe (const or safe name/config)
            return all(
                isinstance(v, ast.Constant) or (isinstance(v, ast.FormattedValue) and self._safe_value(v.value))
                for v in node.values
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._safe_value(node.left) and self._safe_value(node.right)
        return False

    def _is_request_of_safe_url(self, node) -> bool:
        """True if node is urllib...Request(<safe-url>, ...) — a wrapped literal/config URL."""
        if not isinstance(node, ast.Call):
            return False
        if _name(node.func).split(".")[-1] != "Request":
            return False
        url = node.args[0] if node.args else None
        if url is None:
            return False
        # a wrapped literal/config URL, OR a host-pinned URL (constant host, variable path) — both
        # are non-redirectable, so a Request() around either is a safe (allowlisted) fetch target.
        return self._safe_value(url) or self._host_is_pinned(url)

    @staticmethod
    def _bound_names(target) -> list[str]:
        """Names bound by a for-loop target (handles tuple/list unpacking)."""
        out: list[str] = []
        if isinstance(target, ast.Name):
            out.append(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for el in target.elts:
                if isinstance(el, ast.Name):
                    out.append(el.id)
        return out

    def _iterates_safe(self, node) -> bool:
        """True if a for-loop iterable is a module-const / config value (so its loop var is not
        external). Covers ``CONST``, ``CONST.items()``/``.values()``, and ``config.X``."""
        if node is None:
            return False
        if self._safe_value(node):
            return True
        # CONST.items() / CONST.values() / CONST.keys()
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in ("items", "values", "keys"):
            return self._safe_value(node.func.value)
        return False

    def _host_is_pinned(self, node) -> bool:
        """SSRF-specific: True if this URL expression has a CONSTANT scheme+host and only a
        variable *path/query suffix*. Redirecting the fetch to another host is impossible, so it
        is not SSRF (the dominant safe pattern: ``f'{BASE_URL}{path}'`` / ``BASE + path``). We
        approximate 'leading component is a safe constant' — the host is fixed by construction."""
        if isinstance(node, ast.JoinedStr):
            if not node.values:
                return False
            first = node.values[0]
            # leading literal must carry the scheme+authority, e.g. 'http://host/...'
            if isinstance(first, ast.Constant) and isinstance(first.value, str) and "://" in first.value:
                return True
            # or a leading interpolation of a safe (const/config) base URL: f'{BASE}{path}'
            if isinstance(first, ast.FormattedValue) and self._safe_value(first.value):
                return True
            return False
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            # walk to the left-most operand — that's the host-bearing base
            left = node.left
            while isinstance(left, ast.BinOp) and isinstance(left.op, ast.Add):
                left = left.left
            if isinstance(left, ast.Constant) and isinstance(left.value, str) and "://" in left.value:
                return True
            return self._safe_value(left)
        return False

    def is_external_url(self, node) -> bool:
        """SSRF gate: like ``is_external`` but treats a host-PINNED URL (constant scheme+host,
        variable path suffix) as SAFE — you cannot redirect the fetch to an attacker host, so it
        is not SSRF even though a substring is caller-derived."""
        if self._host_is_pinned(node):
            return False
        return self.is_external(node)

    def is_external(self, node) -> bool:
        """The precision gate: is this argument PLAUSIBLY attacker/request/caller-controlled?
        True  → a real lead (param, request object, or a string built from one).
        False → a literal, module-const, config value, or a wrapped-literal Request (SAFE)."""
        if node is None:
            return False
        # a provably-safe local / literal / config value is never external
        if self._safe_value(node):
            return False
        if isinstance(node, ast.Name):
            if node.id in self.safe_request_names or node.id in self.safe_names \
                    or node.id in self.module_consts:
                return False
            if node.id in self.params:
                return True
            # a request-shaped local name (request/event/payload/body/...) is a lead
            return node.id.lower() in _REQUEST_HINTS
        if isinstance(node, ast.Attribute):
            # request.args / flask.request.json / self.request.body → controllable
            dotted = _name(node).lower()
            return any(h in dotted.split(".") for h in _REQUEST_HINTS)
        if isinstance(node, ast.Subscript):
            # request.args['u'] / payload['url'] → follow the receiver
            return self.is_external(node.value)
        if isinstance(node, ast.JoinedStr):
            # an f-string is a lead iff ANY interpolated piece is external
            return any(isinstance(v, ast.FormattedValue) and self.is_external(v.value)
                       for v in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.is_external(node.left) or self.is_external(node.right)
        if isinstance(node, ast.Call):
            # unknown call result: not a lead unless an argument is external (e.g. sanitize(user))
            return any(self.is_external(a) for a in node.args)
        return False


class _ScopeIndex:
    """Maps each Call node to the _Scope of its innermost enclosing function (module scope if
    top-level). Built once per tree; scopes are memoized per function node."""

    def __init__(self, tree: ast.AST):
        self._module = tree
        self._parent: dict[int, ast.AST] = {}
        self._func_of: dict[int, ast.AST | None] = {}
        self._scopes: dict[int, _Scope] = {}
        stack: list[ast.AST | None] = [None]  # current enclosing function
        self._build(tree, stack)

    def _build(self, node, stack):
        cur_func = stack[-1]
        for child in ast.iter_child_nodes(node):
            self._func_of[id(child)] = cur_func
            is_func = isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            stack.append(child if is_func else cur_func)
            self._build(child, stack)
            stack.pop()

    def scope_for(self, call: ast.Call) -> "_Scope":
        func = self._func_of.get(id(call))
        key = id(func) if func is not None else 0
        sc = self._scopes.get(key)
        if sc is None:
            sc = _Scope(self._module, func)
            self._scopes[key] = sc
        return sc


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


# ── R4: SSRF — server-side fetch of a caller/model-controlled URL ────────────────────────
# HTTP-client leaf methods that take a URL as the first positional arg.
_HTTP_VERBS = ("get", "post", "put", "delete", "patch", "head", "options", "request")
# module leaves whose *.get/.post/... are HTTP clients (aliased imports collapse to the leaf)
_HTTP_CLIENTS = ("requests", "httpx", "aiohttp", "session", "client", "clientsession")
# direct urllib entrypoints (dotted-leaf) that fetch a URL from arg0
_URLOPEN_LEAVES = ("urlopen",)


def _is_literal_url(node) -> bool:
    """A URL argument is a *literal* (allowlisted-by-construction) iff it is a plain
    string constant. A Name / attribute / f-string / concatenation is caller-controlled."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _http_url_arg(call: ast.Call):
    """Return the URL argument node for an HTTP-client call, or None if this call is not
    a URL fetch we understand. Handles ``requests.get(url)`` / ``httpx.post(url,...)`` /
    ``session.request('GET', url)`` / ``urlopen(url)``."""
    dotted = _name(call.func)
    parts = dotted.split(".")
    leaf = parts[-1]
    parent = parts[-2].lower() if len(parts) >= 2 else ""
    # requests.get(url) / httpx.get(url) / <session>.get(url) style
    if leaf in _HTTP_VERBS and (parent in _HTTP_CLIENTS or "session" in parent or "client" in parent):
        if leaf == "request":
            # request(method, url, ...) → url is the 2nd positional
            return call.args[1] if len(call.args) >= 2 else None
        return call.args[0] if call.args else None
    # urllib.request.urlopen(url) / bare urlopen(url)
    if leaf in _URLOPEN_LEAVES:
        return call.args[0] if call.args else None
    return None


def _unwrap_request_url(node):
    """If ``node`` is an inline ``Request(url, ...)`` call, return its URL arg (the thing actually
    fetched). Otherwise return ``node`` unchanged. Lets ``urlopen(Request(url))`` see through the
    wrapper to the real URL — while ``urlopen(req)`` is resolved via the scope's safe_request_names."""
    if isinstance(node, ast.Call) and _name(node.func).split(".")[-1] == "Request":
        return node.args[0] if node.args else node
    return node


def scan_ssrf_url_fetch(tree: ast.AST, *, file: str, target: str, program: str) -> list:
    """Flag an HTTP fetch ONLY when the URL is plausibly attacker/request/caller-controlled — a
    function parameter, a request/event object, or a string built from one. A literal URL, a
    module-level constant/config URL, or a ``Request(...)`` wrapping any of those is treated as an
    in-code allowlist and is NOT flagged (that wrapped-literal-Request / constant-base-URL pattern
    was the dominant false positive). Lead-only: confirms the URL is non-literal AND has a
    plausible external source; a human still verifies the taint reaches an untrusted boundary."""
    index = _ScopeIndex(tree)
    drafts = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        url_arg = _http_url_arg(node)
        if url_arg is None or _is_literal_url(url_arg):
            continue
        scope = index.scope_for(node)
        # see through an inline Request(...) wrapper to the URL it carries
        effective = _unwrap_request_url(url_arg)
        # is_external_url (not is_external): a host-pinned URL (constant scheme+host, variable path
        # suffix) is NOT SSRF — the fetch cannot be redirected to an attacker-chosen host.
        if not scope.is_external_url(effective):
            continue
        dotted = _name(node.func)
        drafts.append(_draft(
            target, program, "ssrf-url-fetch",
            f"Server-side fetch of an externally-derived URL via {dotted}()",
            "high",
            f"`{dotted}()` fetches a URL derived from a parameter/request/external input (not a "
            f"literal or module constant) — if that source is caller/model-controlled this is SSRF",
            file, node.lineno, {"sink": dotted}))
    return drafts


# ── R5: hardcoded secret literal in source ───────────────────────────────────────────────
# value-shape patterns that look like real credentials (not just any string)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"^sk-[A-Za-z0-9_\-]{16,}$"),          # OpenAI-style / generic sk- key
    re.compile(r"^AKIA[0-9A-Z]{16}$"),                # AWS access key id
    re.compile(r"^ghp_[A-Za-z0-9]{20,}$"),            # GitHub PAT
    re.compile(r"^xox[baprs]-[A-Za-z0-9-]{10,}$"),    # Slack token
    re.compile(r"^[A-Fa-f0-9]{32,}$"),                # long hex (>=32) — API secret / hash key
    re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$"),        # long base64 blob (>=40)
)


# obvious non-secret markers: placeholders, honeypots, examples, and test bait. A value carrying
# any of these is a deliberately-fake credential (the dominant hardcoded-secret false positive —
# e.g. an ``EXAMPLE`` AWS key or a planted ``sk-honeypot-…`` bait) and must NOT be flagged.
_FAKE_SECRET_MARKERS = ("example", "honeypot", "do-not", "donotuse", "dummy", "placeholder",
                        "changeme", "your-", "yourkey", "xxxx", "redacted", "sample",
                        "fake", "notreal", "sanitized", "deadbeefdeadbeef")


def _looks_secret_value(text: str) -> bool:
    """True if the string literal has the SHAPE of a real credential AND is not an obvious
    placeholder/example/honeypot. Conservative on both ends: a short or human-word value
    (e.g. 'changeme', 'password') does NOT match the shape; and a shaped-but-fake value
    (AKIA…EXAMPLE, sk-honeypot-…, test/dummy tokens) is excluded so bait/fixtures don't fire."""
    if not isinstance(text, str):
        return False
    t = text.strip()
    if not any(p.match(t) for p in _SECRET_VALUE_PATTERNS):
        return False
    low = t.lower()
    if any(m in low for m in _FAKE_SECRET_MARKERS):
        return False
    return True


def scan_hardcoded_secret(tree: ast.AST, *, file: str, target: str, program: str) -> list:
    """Flag ``<secret-shaped-name> = "<secret-shaped-literal>"`` and secret-named kwargs bound
    to a secret-shaped literal. Requires BOTH a secret-shaped *name* AND a credential-shaped
    *value* — a random long hex assigned to a non-secret name is not flagged (precision)."""
    drafts = []

    def _flag(name_text: str, value: str, lineno: int):
        drafts.append(_draft(
            target, program, "hardcoded-secret",
            f"Hardcoded secret assigned to {name_text}",
            "high",
            f"`{name_text}` is assigned a credential-shaped string literal in source — move it "
            f"to a secret store / environment variable, and rotate the exposed value",
            file, lineno, {"name": name_text}))

    for node in ast.walk(tree):
        # assignment: api_key = "sk-…"  /  self.token = "AKIA…"
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            if not (isinstance(node.value.value, str) and _looks_secret_value(node.value.value)):
                continue
            for tgt in node.targets:
                nm = _name(tgt)
                if _looks_secret(nm):
                    _flag(nm, node.value.value, node.lineno)
        # annotated assignment: api_key: str = "sk-…"
        elif isinstance(node, ast.AnnAssign) and node.value is not None \
                and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) \
                and _looks_secret_value(node.value.value):
            nm = _name(node.target)
            if _looks_secret(nm):
                _flag(nm, node.value.value, node.lineno)
        # secret-named kwarg: connect(password="…AKIA…style…") — name+value both secret-shaped
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg and _looks_secret(kw.arg) and isinstance(kw.value, ast.Constant) \
                        and isinstance(kw.value.value, str) and _looks_secret_value(kw.value.value):
                    _flag(kw.arg, kw.value.value, node.lineno)
    return drafts


# ── R6: template injection (SSTI) ────────────────────────────────────────────────────────
_TEMPLATE_CTORS = ("Template",)          # jinja2.Template / any Template(...)
_FROM_STRING_LEAVES = ("from_string",)   # env.from_string(...)


def scan_template_injection(tree: ast.AST, *, file: str, target: str, program: str) -> list:
    """Two leads: (a) a jinja2 ``Environment(autoescape=False)`` (XSS via unescaped output),
    and (b) a ``Template(<non-literal>)`` / ``env.from_string(<non-literal>)`` where the
    template *text* is caller-controlled (server-side template injection)."""
    drafts = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _name(node.func)
        leaf = dotted.split(".")[-1]

        # (a) Environment(autoescape=False) — explicit disabling of autoescape
        if leaf == "Environment":
            for kw in node.keywords:
                if kw.arg == "autoescape" and isinstance(kw.value, ast.Constant) \
                        and kw.value.value is False:
                    drafts.append(_draft(
                        target, program, "template-injection",
                        "jinja2 Environment created with autoescape=False",
                        "high",
                        "`Environment(autoescape=False)` renders template output unescaped — "
                        "any caller-controlled value in a template becomes an XSS/SSTI lead",
                        file, node.lineno, {"sink": dotted}))

        # (b) Template(<non-literal>) / env.from_string(<non-literal>) — SSTI from dynamic text
        elif leaf in _TEMPLATE_CTORS or leaf in _FROM_STRING_LEAVES:
            if node.args and not _is_literal_url(node.args[0]):  # non-literal template text
                drafts.append(_draft(
                    target, program, "template-injection",
                    f"Template constructed from a non-literal via {dotted}()",
                    "high",
                    f"`{dotted}()` builds a template from a non-literal (variable/param) string — "
                    f"if that string is caller/model-controlled this is server-side template "
                    f"injection (SSTI)",
                    file, node.lineno, {"sink": dotted}))
    return drafts


# ── R7: command injection ────────────────────────────────────────────────────────────────
_SUBPROCESS_LEAVES = ("run", "call", "check_call", "check_output", "Popen")
_OS_SHELL_LEAVES = ("system", "popen")


def scan_command_injection(tree: ast.AST, *, file: str, target: str, program: str) -> list:
    """Flag ``subprocess.*(cmd, shell=True)`` where ``cmd`` is a non-literal, and
    ``os.system``/``os.popen`` with a non-literal argument. A string literal command is treated
    as static (not flagged); a variable / f-string / concatenation is the injection lead."""
    drafts = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _name(node.func)
        parts = dotted.split(".")
        leaf = parts[-1]
        parent = parts[-2].lower() if len(parts) >= 2 else ""

        # subprocess.<run/call/Popen>(cmd, ..., shell=True)
        if leaf in _SUBPROCESS_LEAVES and ("subprocess" in parent or parent == ""):
            shell_true = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                             and kw.value.value is True for kw in node.keywords)
            if shell_true and node.args and not _is_literal_url(node.args[0]):
                drafts.append(_draft(
                    target, program, "command-injection",
                    f"subprocess call with shell=True and a non-literal command via {dotted}()",
                    "high",
                    f"`{dotted}(..., shell=True)` runs a non-literal command through the shell — "
                    f"if any part is caller/model-controlled this is command injection",
                    file, node.lineno, {"sink": dotted}))

        # os.system(cmd) / os.popen(cmd) with a non-literal argument
        elif leaf in _OS_SHELL_LEAVES and (parent == "os" or parent == ""):
            if node.args and not _is_literal_url(node.args[0]):
                drafts.append(_draft(
                    target, program, "command-injection",
                    f"{dotted}() invoked with a non-literal command",
                    "high",
                    f"`{dotted}()` passes a non-literal argument straight to the shell — a "
                    f"caller/model-controlled value here is command injection",
                    file, node.lineno, {"sink": dotted}))
    return drafts


# ── module entry ────────────────────────────────────────────────────────────────────────
_RULE_FUNCS = (scan_unsafe_deser, scan_plaintext_secret, scan_world_readable_secret,
               scan_ssrf_url_fetch, scan_hardcoded_secret, scan_template_injection,
               scan_command_injection)


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
