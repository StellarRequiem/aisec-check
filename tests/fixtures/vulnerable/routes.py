"""Vulnerable fixture: access-control asymmetry, IDOR, secret leak, SSRF.

Synthetic — mirrors the shapes the vendored access-control scanner keys on. Not a real app.
"""
import requests
from fastapi import Depends, FastAPI

app = FastAPI()


def get_current_user():
    ...


# gated sibling — establishes intent that this file authenticates some routes
@app.get("/me")
def me(user=Depends(get_current_user)):
    return {"user": user}


# AUTH ASYMMETRY: ungated route beside the gated one above
@app.get("/admin/users")
def list_all_users():
    return {"users": ["everyone"]}


# IDOR: client-supplied id, no auth dependency
@app.get("/orders/{order_id}")
def get_order(order_id: str):
    return {"order": order_id}


# SECRET LEAK: serialises an api_key field
@app.get("/config")
def config():
    return {"api_key": "leaked", "region": "us"}


# SSRF: user-derived URL into an HTTP client
@app.get("/fetch")
def fetch(url: str):
    return requests.get(url).text
