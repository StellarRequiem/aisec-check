"""Safe fixture: guarded fetch / config-sourced secret / static template / no-shell exec.

Should produce zero findings from the SSRF / hardcoded-secret / template-injection /
command-injection rules.
"""
import os
import subprocess

import requests
from jinja2 import Environment, Template


def fetch_safe():
    # safe: literal URL — an in-call allowlist by construction
    return requests.get("https://api.example.com/health")


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
