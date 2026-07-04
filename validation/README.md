# aisec-check — validation corpus & disposable-sandbox scan harness

## What this measures

aisec-check is a **lexical/AST first-cut** analyzer that emits **leads** — candidate
findings a human must confirm. The open question for any such tool is its **real-world
precision**: on real AI-app code (not our own fixtures), what fraction of the leads it
raises are true positives?

This directory is the apparatus for answering that honestly:

- **`corpus.md`** — a fixed sample of **59 real, public, actively-maintained repos** that
  are aisec-check's actual target audience (MCP servers, LLM agent frameworks, RAG apps/
  platforms, AI-tool/inference/gateway wrappers, model-file libraries with a documented
  deserialization surface, and RAG vector-DB clients). A mix of flagships and smaller
  projects, so precision isn't measured only on the most-hardened code.
- **`corpus-scan.yml`** — a `workflow_dispatch` GitHub Actions job that scans every corpus
  repo and uploads the raw findings as one artifact.
- **`aggregate.py`** — a **pure** reducer that folds the raw findings into per-rule,
  per-severity, per-repo, and overall count tables.

**Precision is NOT computed here.** These counts are only the denominators. A finding's
true/false-positive status is decided in the **next phase — human adjudication** — because
every aisec-check finding is a *lead* by design, never a proof of exploitability. Reporting
a precision number before adjudication would be exactly the kind of unverified claim this
project refuses to make.

## The isolation model (why this is safe)

**Every corpus repo is untrusted third-party code.** The hard rule, learned the hard way:
untrusted code you didn't write is **read-only, never executed** on any host you care
about. A venv is scoping, not a sandbox.

So the mass scan runs **only in the GitHub Actions ephemeral runner** — a fresh VM torn
down after the job. Inside that disposable runner:

1. Each repo is acquired **read-only**: `git clone --depth 1 --no-tags` with
   `core.hooksPath=/dev/null` and submodules off. Shallow, single-branch, no hooks.
2. `aisec-check scan <dir>` runs over the clone. aisec-check is a **read-only lexical/AST
   analyzer** — it *parses source text*. It does **not** import, install, build, or run the
   target. There is **no `pip install` of the cloned repo**, no `setup.py`, no `conftest`,
   no plugin/entrypoint loading, no test execution.
3. The only thing `pip install`-ed is **aisec-check itself** (our own audited code) plus its
   pinned `verity-core` dependency — from *this* repo, never from a clone.
4. The clone is deleted immediately after it is read. Only the **findings artifact** leaves
   the runner. Nothing is ever pulled back to a developer host "to check quickly."

This is the same disposable-runner boundary `mcp-bench` uses to run real third-party
scanners. The comment block at the top of `corpus-scan.yml` restates it inline.

### Host-safety of the tooling in this directory

`aggregate.py` is a **pure function** over already-collected JSON. It reads only the result
files the scan produced — never a target, never the network — so it runs and unit-tests on
any host with no scanner present. That keeps the *parsing/aggregation* logic verifiable
without ever executing an untrusted target.

## Responsible-disclosure posture

A lead that survives adjudication as a **confirmed true positive in a third-party repo is a
security finding, handled by responsible disclosure** — reported privately to the
maintainer (or via the repo's security policy / a program like huntr), on a coordinated
timeline, and **never exploited**. aisec-check is a defensive read-only analyzer; this
corpus exists to measure and improve it, not to attack anyone. No target is ever run,
weaponized, or disclosed publicly ahead of the maintainer.

## Running it

```sh
# In the aisec-check repo on GitHub → Actions → "corpus-scan" → Run workflow.
# (workflow_dispatch only — a deliberate, on-demand measurement run.)

# Then, locally, over the downloaded artifact (pure, host-safe):
python validation/aggregate.py path/to/findings --md report.md --out report.json
```

The workflow file lives at `validation/corpus-scan.yml`; to activate it in CI, move/copy it
under `.github/workflows/`.
