"""Unit tests for the new AST rules (unsafe-deser / plaintext-secret / world-readable)."""
from aisec_check import rules


def _classes(src):
    return {d.finding_class for d in rules.scan_source(src, file="t.py", target="t")}


# ── R1: unsafe deserialization ──────────────────────────────────────────────────────────
def test_pickle_loads_flagged():
    assert "unsafe-deserialization" in _classes("import pickle\npickle.loads(b)\n")


def test_torch_load_without_weights_only_flagged():
    assert "unsafe-deserialization" in _classes("import torch\ntorch.load(p)\n")


def test_torch_load_with_weights_only_safe():
    assert "unsafe-deserialization" not in _classes("import torch\ntorch.load(p, weights_only=True)\n")


def test_yaml_load_without_safeloader_flagged():
    assert "unsafe-deserialization" in _classes("import yaml\nyaml.load(text)\n")


def test_yaml_load_with_safeloader_safe():
    assert "unsafe-deserialization" not in _classes("import yaml\nyaml.load(text, Loader=yaml.SafeLoader)\n")


def test_yaml_safe_load_not_flagged():
    # yaml.safe_load is a different, safe call — must not fire
    assert "unsafe-deserialization" not in _classes("import yaml\nyaml.safe_load(text)\n")


# ── R2: plaintext secret storage ────────────────────────────────────────────────────────
def test_secret_path_write_flagged():
    src = "def f(t):\n    with open('api_token.txt', 'w') as fh:\n        fh.write(t)\n"
    assert "plaintext-secret-storage" in _classes(src)


def test_secret_var_written_flagged():
    src = "def f(secret):\n    with open('out.dat', 'w') as fh:\n        fh.write(secret)\n"
    assert "plaintext-secret-storage" in _classes(src)


def test_read_mode_not_flagged():
    src = "def f(p):\n    with open(p, 'r') as fh:\n        return fh.read()\n"
    assert "plaintext-secret-storage" not in _classes(src)


def test_nonsecret_write_not_flagged():
    src = "def f(x):\n    with open('output.log', 'w') as fh:\n        fh.write(x)\n"
    assert "plaintext-secret-storage" not in _classes(src)


# ── R3: world-readable secret ───────────────────────────────────────────────────────────
def test_world_readable_secret_flagged():
    assert "world-readable-secret" in _classes("import os\nos.chmod('credentials.json', 0o644)\n")


def test_restrictive_mode_not_flagged():
    assert "world-readable-secret" not in _classes("import os\nos.chmod('credentials.json', 0o600)\n")


def test_world_readable_nonsecret_not_flagged():
    # world-readable but not a secret path → the rule only flags secret-shaped paths
    assert "world-readable-secret" not in _classes("import os\nos.chmod('public.html', 0o644)\n")


def test_syntax_error_returns_empty():
    assert rules.scan_source("def (:\n", file="t.py", target="t") == []
