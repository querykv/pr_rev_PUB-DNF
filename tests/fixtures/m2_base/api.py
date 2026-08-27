"""FastAPI surface for the M2 detector fixture — the BASE side.

NOT RUN, parsed only. This base/head pair is deliberately separate from the
profiling fixture: those tests assert exact counts against it, so a detector
fixture that shared it could not add a file without breaking them.

Ground truth at base:
  GET /items          Depends(get_current_user)  -> enforced
  GET /legacy/{iid}   no dependency              -> pre-existing missing authz
  LEGACY_TOKEN                                   -> pre-existing hardcoded secret
"""
from fastapi import APIRouter, Depends

from store import Item, get_current_user

LEGACY_TOKEN = "ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"

router = APIRouter()


@router.get("/items")
async def list_items(user=Depends(get_current_user)):
    return Item.all_for(user)


@router.get("/legacy/{iid}")
async def legacy_item(iid: str):
    """No dependency. Already unguarded before this PR — pre-existing."""
    return Item.fetch(iid)
