"""Data layer for the profiling fixture.

NOT RUN — parsed only. Carries the class/inheritance shapes the structural
indexer's type-hierarchy extraction has to resolve, plus sensitive fields for
the privacy/logging family.
"""
import logging

logger = logging.getLogger(__name__)


class BaseModel:
    table = None

    @classmethod
    def fetch(cls, key):
        raise NotImplementedError


class User(BaseModel):
    table = "users"
    # sensitive_fields ground truth
    email = None
    password_hash = None
    ssn = None

    @classmethod
    def fetch(cls, key):
        logger.info("loading user %s", key)
        return {"id": key}


class Item(BaseModel):
    table = "items"

    @classmethod
    def fetch(cls, key):
        return {"id": key}

    @classmethod
    def all_for(cls, user):
        return []


def get_cursor():
    raise NotImplementedError


def get_current_user():
    """The FastAPI auth dependency — a `guards` edge target."""
    raise NotImplementedError
