# aisec-check

A **lexical / AST first-cut** CI linter for the vulnerability classes that recur in
AI-built apps and MCP servers. It scans Python source **read-only**, emits **leads**
(candidate findings a human must confirm), and seals the finding set into a
tamper-evident receipt.

> **Honest scope — read this first.** aisec-check is a *lexical and AST* scanner. It
> matches syntactic shapes — call names, decorator/argument kinds, secret-shaped
> identifiers — **not** data flow, reachability, or semantics. Every finding is a
> **LEAD**: expect false positives and false negatives. It is a cheap first pass that
> tells a reviewer *where to look*, not a proof of exploitability and not a semantic
> analyzer. There is **no track record** claimed here (no benchmark corpus is shipped
> in v0.1); the detectors are deterministic rules, evaluated against the fixtures in
> `tests/fixtures/` only.

## What it checks (the exact rules)

Access-control rules (from a vendored read-only access-control scanner; route-scoped, FastAPI/Flask-style):

| class | what it flags |
|---|---|
| `auth-bypass` | a route handler with **no** auth dependency sitting beside sibling routes in the same file that **do** have one (the asymmetry pattern) |
| `idor` | a handler taking a client-supplied `id`/`user_id`/`*_id` param with no auth dependency (possible BOLA) |
| `secret-leak` | a handler whose body/return references a secret-shaped field (`api_key`, `token`, `client_secret`, …) |
| `ssrf` / `path-traversal` | user-derived (non-constant) input flowing into an HTTP client (`requests`/`httpx`/`urllib`) or a path sink (`open`/`os.path.join`/`str.replace`) |

New rules (this package's delta; file-level AST):

| class | what it flags |
|---|---|
| `unsafe-deserialization` | `pickle.load`/`pickle.loads`/`dill.load`, `torch.load(...)` **without** `weights_only=True`, `yaml.load(...)` **without** a `SafeLoader` |
| `plaintext-secret-storage` | a secret-shaped path opened for **write** (`open("api_token.txt", "w")`), or a `with open(..., "w")` block that writes a secret-shaped variable/literal |
| `world-readable-secret` | `chmod(...)` granting an "other" (world) read/write/execute bit on a secret-shaped path |
| `ssrf-url-fetch` | `requests`/`httpx`/`aiohttp` `.get`/`.post`/… or `urllib` `urlopen(...)` where the URL is a **non-literal** (variable/param/f-string) — a server-side fetch of a caller/model-controlled URL with no in-call literal allowlist |
| `hardcoded-secret` | an assignment (or secret-named kwarg) whose **name** is secret-shaped **and** whose value is a credential-shaped literal (`sk-…`, `AKIA…`, `ghp_…`, `xox…`, long hex, long base64) |
| `template-injection` | `jinja2.Environment(autoescape=False)`, or `Template(...)` / `env.from_string(...)` built from a **non-literal** template string (SSTI lead) |
| `command-injection` | `subprocess.*(..., shell=True)` with a **non-literal** command, or `os.system` / `os.popen` with a non-literal argument |

Each detector is **read-only** and **never runs the target** — it parses source text.

## Usage

```sh
aisec-check scan path/to/repo                          # human-readable; exit = worst severity
aisec-check scan app.py --sarif out.sarif              # SARIF 2.1.0 for CI code-scanning
aisec-check scan repo/ --receipt receipt.json          # + a sealed receipt (audit chain)
aisec-check scan repo/ --json                          # machine-readable findings
aisec-check verify --receipt receipt.json              # re-derive the receipt root
```

**Exit code** (from `scan`) = worst severity: `0` clean · `1` low · `2` medium · `3` high · `4` critical.
Wire it into CI to fail a build above a chosen threshold.

## The sealed receipt

The finding set is sealed with **verity-core**'s canonical-JSON → SHA-256 `entry_hash`
and appended to an append-only `AuditChain` — the same hashing substrate the rest of the
verification-layer family uses, so receipts cross-verify. We do **not** roll our own crypto.

**Threat model (do not overstate):** the receipt root is an **unkeyed** hash. It catches
corruption and naive edits, **not** a determined forger who controls the receipt file and
recomputes the root. Real verification re-runs the scan and re-seals; standing integrity
over time needs the root anchored/published or an HMAC key held by the verifier.
Unkeyed = integrity, not tamper-evidence against a rewrite.

## Third-party scanners & the sandbox

Optional bundled SAST scanners (semgrep/bandit/dlint) are **untrusted third-party code**
and run **only** inside a disposable CI runner (`.github/workflows/scan.yml`, the ephemeral
GitHub Actions VM) — never on a developer host. Their SARIF/JSON output is normalized to
this package's finding schema via **mcp-bench**'s `parse_sarif` (imported, not re-implemented).
The native detectors above need nothing beyond the standard library + verity-core and are
host-safe.

## Provenance / reuse

- The access-control scanner (`acdiff.py`) and its `FindingDraft` model are **vendored**
  (copied, defensive-only, with a provenance note) from an internal local-only research tool
  that has no public remote — it cannot be a git dependency. No offensive code was copied.
- `verity-core` (pinned to one version) supplies the hash chain / sealing.
- `mcp-bench` (Apache-2.0) supplies SARIF parsing + Wilson-interval math for the CI runner.

## Status

v0.1 — a working first cut: a real CLI, a pure detector core with passing unit tests,
fixtures (vulnerable + safe), and a SARIF + sealed-receipt path. Not a polished product.
The ruleset is intentionally small (3 vendored access-control classes + 7 new rule groups),
solid over broad.

License: Apache-2.0.
