"""FastAPI surface for the M2 detector fixture — the HEAD side.

NOT RUN, parsed only. What this PR does, and what each change is here to prove:

  /items loses `Depends(get_current_user)`   -> INTRODUCED, guard removed (structural
                                                sees it only by comparing both graphs)
  /search is new, unguarded, and taints SQL  -> INTRODUCED, critical (unauthenticated
                                                reachability raises it)
  /legacy/{iid} is untouched and unguarded   -> PRE-EXISTING: present in the baseline,
                                                so the PR is not blamed for it
  SESSION_KEY is new                         -> INTRODUCED secret, validated, gates
  LEGACY_TOKEN moved down the file           -> PRE-EXISTING: the diff shows it as an
                                                added line, and only the baseline can
                                                tell that a moved line is not a new secret
"""
from fastapi import APIRouter, Request

from store import Item, get_cursor

router = APIRouter()

SESSION_KEY = "ghp_9z8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k3j2i"
LEGACY_TOKEN = "ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"


@router.get("/items")
async def list_items():
    return Item.all()


@router.get("/legacy/{iid}")
async def legacy_item(iid: str):
    """No dependency. Already unguarded before this PR — pre-existing."""
    return Item.fetch(iid)


@router.get("/search")
async def search_items(request: Request):
    term = request.query_params.get("q")
    return _query(term)


def _query(term):
    cursor = get_cursor()
    return cursor.execute(f"SELECT * FROM items WHERE name = '{term}'")
