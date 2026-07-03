"""Vulnerable fixture: SSRF / hardcoded-secret / template-injection / command-injection."""
import os
import subprocess

import httpx
import requests
from jinja2 import Environment, Template
from urllib.request import urlopen


def fetch_bad(url):
    # R4: server-side fetch of a caller-controlled URL (no literal allowlist)
    return requests.get(url)


def fetch_bad2(target):
    # R4: httpx.post to a non-literal URL
    return httpx.post(target, json={})


def fetch_bad3(loc):
    # R4: urllib.urlopen on a variable
    return urlopen(loc)


# R5: hardcoded credential-shaped literals in source
API_KEY = "sk-abcdef0123456789abcdef0123456789"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"


def render_bad(user_template):
    # R6: SSTI — template text is caller-controlled
    return Template(user_template).render()


def make_env_bad():
    # R6: autoescape disabled
    return Environment(autoescape=False)


def run_bad(user_cmd):
    # R7: shell=True with a non-literal command
    return subprocess.run(user_cmd, shell=True)


def run_bad2(name):
    # R7: os.system with an f-string built from input
    return os.system(f"echo {name}")
