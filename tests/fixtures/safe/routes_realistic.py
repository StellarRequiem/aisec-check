"""SAFE fixture — legitimate uses of the exact SHAPES the access-control rules key on.

Every route below uses a pattern that the *naive* rules flagged (an id param, a secret word,
an http/path sink) but that is actually SAFE. A hardened acdiff must stay SILENT here — these are
the dominant real-world false-positive shapes. Synthetic; not a real app.
"""
import os

import requests
from fastapi import Depends, FastAPI

app = FastAPI()

BASE_DIR = "/srv/app/static"
UPSTREAM = "https://api.internal.example.com"


def get_current_user():
    ...


# gated sibling establishes that this file authenticates routes (so asymmetry could fire)
@app.get("/me")
def me(user=Depends(get_current_user)):
    return {"user": user}


# SAFE (not IDOR): has an id param but the lookup is bound to the authenticated owner.
@app.get("/orders/{order_id}")
def get_order(order_id: str, user=Depends(get_current_user)):
    return {"order": Order.query.filter_by(id=order_id, owner_id=user.id).first()}


# SAFE (not IDOR): id param is only echoed/logged, never used to look anything up.
@app.get("/echo/{item_id}")
def echo_item(item_id: str, user=Depends(get_current_user)):
    return {"echoed": item_id}


# SAFE (not secret-leak): references a password to HASH it, never returns it.
@app.post("/register")
def register(password: str, user=Depends(get_current_user)):
    hashed = hash_password(password)
    save(hashed)
    return {"status": "ok"}


# SAFE (not SSRF): the http sink fetches a module-const upstream URL, not a param.
@app.get("/status")
def status(user=Depends(get_current_user)):
    return requests.get(UPSTREAM + "/health").json()


# SAFE (not path-traversal): open() of a module-const path in read mode.
@app.get("/banner")
def banner(user=Depends(get_current_user)):
    with open(BASE_DIR + "/banner.txt", "r") as fh:
        return {"banner": fh.read()}
