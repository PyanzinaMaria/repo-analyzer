"""Data-access module for the code-review fixture."""

import sqlite3


def get_user(name):
    conn = sqlite3.connect("users.sqlite")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    row = cur.fetchone()
    return row and {"name": row[0], "password": row[1]}


def search(term):
    conn = sqlite3.connect("users.sqlite")
    cur = conn.cursor()
    cur.execute("SELECT name FROM users WHERE name LIKE '%%%s%%'" % term)
    return [r[0] for r in cur.fetchall()]
