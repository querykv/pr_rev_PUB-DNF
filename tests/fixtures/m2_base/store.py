"""Data access for the M2 fixture. Identical on both sides, so it never appears
in the diff — a file the PR does not touch must not attract findings."""


class Item:
    @staticmethod
    def all():
        return []

    @staticmethod
    def all_for(user):
        return []

    @staticmethod
    def fetch(iid):
        return {"id": iid}


def get_current_user():
    return {"id": 1}


def get_cursor():
    return _CONNECTION.cursor()


_CONNECTION = None
