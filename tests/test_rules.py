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


# ── R4: SSRF — server-side fetch of a non-literal URL ────────────────────────────────────
def test_requests_get_variable_url_flagged():
    assert "ssrf-url-fetch" in _classes("import requests\ndef f(url):\n    return requests.get(url)\n")


def test_httpx_post_variable_url_flagged():
    assert "ssrf-url-fetch" in _classes("import httpx\ndef f(u):\n    return httpx.post(u, json={})\n")


def test_urlopen_variable_flagged():
    src = "from urllib.request import urlopen\ndef f(u):\n    return urlopen(u)\n"
    assert "ssrf-url-fetch" in _classes(src)


def test_requests_get_literal_url_safe():
    src = "import requests\nrequests.get('https://api.example.com/health')\n"
    assert "ssrf-url-fetch" not in _classes(src)


def test_session_request_method_url_flagged():
    # session.request('GET', url) → url is the 2nd positional and non-literal.
    # Receiver must be a client-shaped name ('session'/'client') to keep the rule precise —
    # a bare local like `s` is intentionally NOT matched.
    src = "def f(session, url):\n    return session.request('GET', url)\n"
    assert "ssrf-url-fetch" in _classes(src)


# ── R4 SAFE patterns: the dominant real-infra false positives that must NOT fire ─────────
def test_ssrf_module_const_url_safe():
    # requests.get(MODULE_CONST) — a config/base URL, not attacker input
    src = "import requests\nAPI = 'https://api.example.com/health'\nrequests.get(API)\n"
    assert "ssrf-url-fetch" not in _classes(src)


def test_ssrf_wrapped_request_const_url_safe():
    # urlopen(Request(MODULE_CONST)) — the wrapped-literal-Request infra pattern
    src = ("import urllib.request\nURL = 'http://127.0.0.1:8800/x'\n"
           "def f():\n    req = urllib.request.Request(URL)\n    return urllib.request.urlopen(req)\n")
    assert "ssrf-url-fetch" not in _classes(src)


def test_ssrf_host_pinned_path_suffix_safe():
    # f'{BASE}{path}' — constant host, only the PATH varies → not redirectable → not SSRF
    src = ("import requests\nBASE = 'https://api.example.com'\n"
           "def f(path):\n    return requests.get(f'{BASE}{path}')\n")
    assert "ssrf-url-fetch" not in _classes(src)


def test_ssrf_const_base_concat_safe():
    # BASE + '/literal' — host pinned by a module const
    src = ("import requests\nBASE = 'https://api.example.com'\n"
           "def f():\n    return requests.get(BASE + '/v1/status')\n")
    assert "ssrf-url-fetch" not in _classes(src)


def test_ssrf_config_loop_var_safe():
    # for url in FEEDS.values(): urlopen(Request(url)) — loop var over a module-const dict
    src = ("import urllib.request\nFEEDS = {'a': 'https://x.example/rss'}\n"
           "def f():\n    for name, url in FEEDS.items():\n"
           "        req = urllib.request.Request(url)\n        urllib.request.urlopen(req)\n")
    assert "ssrf-url-fetch" not in _classes(src)


def test_ssrf_param_url_still_flagged():
    # regression guard: a genuinely param-derived URL (no host pin) MUST still fire
    src = "import requests\ndef f(url):\n    return requests.get(url)\n"
    assert "ssrf-url-fetch" in _classes(src)


# ── R5: hardcoded secret literal ─────────────────────────────────────────────────────────
def test_hardcoded_openai_key_flagged():
    src = "api_key = 'sk-Jk3nQ8vRtLpW2xYz7bMdF4aH'\n"
    assert "hardcoded-secret" in _classes(src)


def test_hardcoded_aws_key_flagged():
    src = "AWS_ACCESS_KEY_ID = 'AKIAJ7QK3NP2WXYZ4RTL'\n"
    assert "hardcoded-secret" in _classes(src)


def test_secret_kwarg_literal_flagged():
    src = "connect(password='AKIAJ7QK3NP2WXYZ4RTL')\n"
    assert "hardcoded-secret" in _classes(src)


def test_secret_name_nonsecret_value_safe():
    # secret-shaped NAME but the value is not credential-shaped → not flagged (precision)
    assert "hardcoded-secret" not in _classes("api_key = 'API_KEY'\n")


def test_secretshaped_value_nonsecret_name_safe():
    # a long hex value bound to a non-secret name → not flagged (requires both)
    assert "hardcoded-secret" not in _classes("checksum = '" + "a" * 40 + "'\n")


def test_honeypot_bait_token_not_flagged():
    # a deliberately-fake honeypot/bait credential must NOT fire (dominant secret FP)
    src = "HONEYPOT_TOKEN = 'sk-honeypot-DO-NOT-EXFILTRATE-7f3a91'\n"
    assert "hardcoded-secret" not in _classes(src)


def test_example_aws_key_not_flagged():
    # AWS docs 'EXAMPLE' key — a placeholder, not a live credential
    assert "hardcoded-secret" not in _classes("AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n")


# ── R6: template injection (SSTI) ────────────────────────────────────────────────────────
def test_environment_autoescape_false_flagged():
    src = "from jinja2 import Environment\nEnvironment(autoescape=False)\n"
    assert "template-injection" in _classes(src)


def test_template_from_variable_flagged():
    src = "from jinja2 import Template\ndef f(t):\n    return Template(t).render()\n"
    assert "template-injection" in _classes(src)


def test_from_string_variable_flagged():
    src = "def f(env, t):\n    return env.from_string(t)\n"
    assert "template-injection" in _classes(src)


def test_template_literal_safe():
    src = "from jinja2 import Template\nTemplate('Hi {{ name }}').render(name='x')\n"
    assert "template-injection" not in _classes(src)


def test_environment_autoescape_true_safe():
    src = "from jinja2 import Environment\nEnvironment(autoescape=True)\n"
    assert "template-injection" not in _classes(src)


# ── R7: command injection ────────────────────────────────────────────────────────────────
def test_subprocess_shell_true_variable_flagged():
    src = "import subprocess\ndef f(cmd):\n    return subprocess.run(cmd, shell=True)\n"
    assert "command-injection" in _classes(src)


def test_os_system_fstring_flagged():
    src = "import os\ndef f(name):\n    return os.system(f'echo {name}')\n"
    assert "command-injection" in _classes(src)


def test_os_popen_variable_flagged():
    src = "import os\ndef f(c):\n    return os.popen(c)\n"
    assert "command-injection" in _classes(src)


def test_subprocess_argv_list_safe():
    # no shell, argv list → not flagged
    src = "import subprocess\ndef f(name):\n    return subprocess.run(['echo', name])\n"
    assert "command-injection" not in _classes(src)


def test_subprocess_shell_true_literal_safe():
    # shell=True but a fully-literal command → static, not flagged
    src = "import subprocess\nsubprocess.run('ls -la', shell=True)\n"
    assert "command-injection" not in _classes(src)


# ── fixtures: vulnerable fires, safe is silent (mirrors deser_secrets fixture pair) ───────
_NEW_CLASSES = {"ssrf-url-fetch", "hardcoded-secret", "template-injection", "command-injection"}


def _fixture_classes(kind):
    import pathlib
    p = pathlib.Path(__file__).parent / "fixtures" / kind / "webfetch_exec.py"
    return {d.finding_class for d in rules.scan_source(p.read_text(), file="webfetch_exec.py", target="t")}


def test_vulnerable_fixture_fires_all_new_rules():
    assert _NEW_CLASSES <= _fixture_classes("vulnerable")


def test_safe_fixture_silent_on_new_rules():
    assert not (_NEW_CLASSES & _fixture_classes("safe"))


def test_syntax_error_returns_empty():
    assert rules.scan_source("def (:\n", file="t.py", target="t") == []
