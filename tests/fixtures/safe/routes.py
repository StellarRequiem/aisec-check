"""Safe fixture: every route gated, no IDOR/secret-leak/SSRF shapes. Should produce zero findings."""
from fastapi import Depends, FastAPI

app = FastAPI()


def get_current_user():
    ...


@app.get("/me")
def me(user=Depends(get_current_user)):
    return {"user": user}


@app.get("/admin/users")
def list_all_users(user=Depends(get_current_user)):
    # gated — no asymmetry
    return {"users": ["everyone"]}


@app.get("/orders")
def get_order(user=Depends(get_current_user)):
    # no client-supplied id param; owner comes from the authenticated user
    return {"orders": []}


@app.get("/config")
def config(user=Depends(get_current_user)):
    # no secret-shaped field serialised
    return {"region": "us"}
