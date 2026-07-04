"""Safe fixture: guarded fetch / config-sourced secret / static template / no-shell exec.

Should produce zero findings from the SSRF / hardcoded-secret / template-injection /
command-injection rules.
"""
import os
import subprocess
import urllib.request

import requests
from jinja2 import Environment, Template

# module-level constants — config/base values, NOT attacker input
BASE_URL = "https://api.example.com"
OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
FEEDS = {"hn": "https://news.example.com/rss", "lo": "https://blog.example.com/rss"}
# a deliberately-fake honeypot credential (bait) — must NOT be flagged as a real hardcoded secret
HONEYPOT_TOKEN = "sk-honeypot-DO-NOT-EXFILTRATE-7f3a91"


def fetch_safe():
    # safe: literal URL — an in-call allowlist by construction
    return requests.get("https://api.example.com/health")


def fetch_const_base():
    # safe: URL built from a module-const base + a literal path (host is pinned)
    return requests.get(BASE_URL + "/v1/status")


def fetch_host_pinned(path):
    # safe: host+scheme are a constant; only the PATH suffix varies → not redirectable → not SSRF
    return requests.get(f"{BASE_URL}{path}")


def fetch_wrapped_request():
    # safe: urlopen(Request(<module-const URL>)) — the dominant real-infra pattern
    req = urllib.request.Request(OLLAMA_URL, data=b"{}", headers={"Content-Type": "application/json"})
    return urllib.request.urlopen(req, timeout=30).read()


def fetch_config_loop():
    # safe: loop var iterates a module-const dict — a config value, not caller input
    out = []
    for name, url in FEEDS.items():
        req = urllib.request.Request(url, headers={"User-Agent": "x"})
        out.append(urllib.request.urlopen(req, timeout=5).read())
    return out


def load_key_safe():
    # safe: secret sourced from the environment, not a literal in source
    return os.environ["API_KEY"]


# safe: secret-shaped NAME but the value is not a credential-shaped literal
API_KEY_ENV_VAR = "API_KEY"


def render_safe():
    # safe: template text is a string literal (static)
    return Template("Hello {{ name }}").render(name="world")


def make_env_safe():
    # safe: autoescape enabled
    return Environment(autoescape=True)


def run_safe(name):
    # safe: no shell, argv list (shell metacharacters cannot be injected)
    return subprocess.run(["echo", name])


def run_safe2():
    # safe: shell=True but a fully-literal command (static, not caller-controlled)
    return subprocess.run("ls -la", shell=True)
