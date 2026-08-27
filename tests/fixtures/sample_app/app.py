"""Flask surface for the profiling fixture.

NOT RUN — parsed only. This file is deliberately insecure in specific, labelled
ways so `profile/promote.py`, `profile/cpg.py` and the M1 acceptance test have a
target with a known-correct answer (phase-1 §10).

Ground truth encoded here:
  /public          GET       no guard          -> enforcement="none"
  /profile/<uid>   GET       @login_required   -> enforcement="enforced"
  /admin/export    POST      no guard          -> enforcement="none", admin-ish
  search()         request.args -> cursor.execute (unsanitized)  -> INJ-SQLI
"""
from flask import Flask, request
from flask_login import login_required

from models import User, get_cursor

app = Flask(__name__)


@app.route("/public", methods=["GET"])
def public_index():
    return {"ok": True}


@app.route("/profile/<uid>", methods=["GET"])
@login_required
def get_profile(uid):
    return User.fetch(uid)


@app.route("/admin/export", methods=["POST"])
def admin_export():
    """No guard despite the path — the interesting row in the matrix."""
    return _dump_all()


@app.route("/search", methods=["GET"])
@login_required
def search():
    term = request.args.get("q")
    return _run_search(term)


def _run_search(term):
    cursor = get_cursor()
    # source -> sink, no parameter binding: the planted SQLi
    cursor.execute("SELECT * FROM items WHERE name LIKE '%" + term + "%'")
    return cursor.fetchall()


def _dump_all():
    cursor = get_cursor()
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()
