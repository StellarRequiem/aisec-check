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
    # realistic IDOR: looks up by the client id with no owner/current_user binding
    return {"o": Order.query.get(order_id)}

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


# ── SAFE patterns: legitimate uses of the flagged shapes must NOT fire ────────────────────
def test_idor_owner_bound_not_flagged():
    # id param but the lookup is scoped to the authenticated owner → not IDOR
    src = ('from fastapi import Depends\n'
           '@app.get("/o/{oid}")\n'
           'def g(oid: str, user=Depends(auth)):\n'
           '    return Order.query.filter_by(id=oid, owner_id=user.id).first()\n')
    assert "idor" not in _classes(src)


def test_idor_id_only_echoed_not_flagged():
    # id param never used in a lookup (just echoed) → not IDOR
    src = ('@app.get("/e/{item_id}")\n'
           'def e(item_id: str):\n    return {"echoed": item_id}\n')
    assert "idor" not in _classes(src)


def test_secret_leak_password_hashed_not_flagged():
    # references 'password' to hash it, never returns it → not a secret leak
    src = ('@app.post("/reg")\n'
           'def reg(password: str):\n    h = hash_password(password)\n    return {"ok": True}\n')
    assert "secret-leak" not in _classes(src)


def test_ssrf_module_const_url_in_route_not_flagged():
    # http sink fed a module-const URL, not a param → not SSRF
    src = ('import requests\nUP = "https://api.internal"\n'
           '@app.get("/s")\ndef s():\n    return requests.get(UP + "/health").json()\n')
    assert "ssrf" not in _classes(src)


def test_path_read_const_not_flagged():
    # open() of a module-const path in read mode → not path-traversal
    src = ('BASE = "/srv/static"\n'
           '@app.get("/b")\ndef b():\n    return open(BASE + "/x.txt", "r").read()\n')
    assert "path-traversal" not in _classes(src)


def test_ssrf_param_url_in_route_still_flagged():
    # regression: a param-derived URL into an http sink MUST still fire
    src = ('import requests\n'
           '@app.get("/f")\ndef f(url: str):\n    return requests.get(url).text\n')
    assert "ssrf" in _classes(src)


def _fixture_classes_ac(kind, fname):
    import pathlib
    p = pathlib.Path(__file__).parent / "fixtures" / kind / fname
    return {d.finding_class for d in acdiff.scan_source(p.read_text(), file=fname, target="t")}


def test_safe_realistic_routes_silent_on_ac_rules():
    # the realistic safe fixture uses every flagged SHAPE legitimately → zero access-control leads
    cls = _fixture_classes_ac("safe", "routes_realistic.py")
    assert not ({"idor", "secret-leak", "ssrf", "path-traversal"} & cls)
