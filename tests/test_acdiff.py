"""Unit tests for the vendored access-control scanner (auth/idor/secret-leak/ssrf)."""
from aisec_check import acdiff

_VULN = '''\
import requests
from fastapi import Depends, FastAPI
app = FastAPI()
def get_current_user(): ...

@app.get("/me")
def me(user=Depends(get_current_user)):
    return {"user": user}

@app.get("/admin")
def admin():
    return {"all": 1}

@app.get("/orders/{order_id}")
def get_order(order_id: str):
    return {"o": order_id}

@app.get("/config")
def config():
    return {"api_key": "x"}

@app.get("/fetch")
def fetch(url: str):
    return requests.get(url).text
'''

_SAFE = '''\
from fastapi import Depends, FastAPI
app = FastAPI()
def get_current_user(): ...

@app.get("/me")
def me(user=Depends(get_current_user)):
    return {"user": user}

@app.get("/admin")
def admin(user=Depends(get_current_user)):
    return {"all": 1}
'''


def _classes(src):
    return {d.finding_class for d in acdiff.scan_source(src, file="r.py", target="t")}


def test_auth_asymmetry_flagged():
    assert "auth-bypass" in _classes(_VULN)


def test_idor_flagged():
    assert "idor" in _classes(_VULN)


def test_secret_leak_flagged():
    assert "secret-leak" in _classes(_VULN)


def test_ssrf_flagged():
    assert "ssrf" in _classes(_VULN)


def test_all_gated_no_asymmetry():
    # every route gated → no auth-bypass, no idor
    cls = _classes(_SAFE)
    assert "auth-bypass" not in cls
    assert "idor" not in cls


def test_syntax_error_returns_empty():
    assert acdiff.scan_source("def (:\n", file="r.py", target="t") == []
