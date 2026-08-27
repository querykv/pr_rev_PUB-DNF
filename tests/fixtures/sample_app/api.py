"""FastAPI surface for the profiling fixture.

NOT RUN — parsed only. FastAPI expresses authorization as an injected dependency
rather than a decorator, which is why promote.py has to read parameters and not
just decorators (phase-1 §3).

Ground truth encoded here:
  GET  /items          Depends(get_current_user)  -> enforcement="enforced"
  GET  /items/{iid}    no dependency              -> enforcement="none"  (IDOR)
  POST /run            no dependency, cmd sink    -> enforcement="none"  (INJ-CMD)
"""
import subprocess

from fastapi import APIRouter, Depends, Request

from models import Item, get_current_user

router = APIRouter()


@router.get("/items")
async def list_items(user=Depends(get_current_user)):
    return Item.all_for(user)


@router.get("/items/{iid}")
async def get_item(iid: str):
    """No dependency — any caller reads any item. Planted IDOR."""
    return Item.fetch(iid)


@router.post("/run")
async def run_task(request: Request):
    body = await request.json()
    return _spawn(body["cmd"])


def _spawn(cmd):
    # source -> sink with shell=True: the planted command injection
    return subprocess.run(cmd, shell=True, capture_output=True)
