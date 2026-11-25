"""Tiny Flask-shaped app used as a code-review fixture (not executed by tests).

It mimics the real pattern: a route reads a request parameter, passes it to a
data-access module whose function runs a raw SQL query. The reviewer must find
the path route -> libdb.get_user -> cursor.execute and attach /login + username.
"""

from flask import Flask, request

import libdb

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def do_login():
    username = request.form.get("username")
    password = request.form.get("password")
    user = libdb.get_user(username)
    if user and user["password"] == password:
        return "ok"
    return "denied", 401


@app.route("/search")
def do_search():
    q = request.args.get("q")
    return "<html>" + "".join(libdb.search(q)) + "</html>"
