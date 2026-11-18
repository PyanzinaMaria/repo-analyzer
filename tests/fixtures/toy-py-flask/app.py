"""Deliberately vulnerable toy Flask app used as a SAST fixture. DO NOT DEPLOY."""

import os
import pickle
import sqlite3
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)
UPLOAD_DIR = "/srv/uploads"


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    out = subprocess.check_output("ping -c 1 " + host, shell=True)  # PLANT: command injection
    return out


@app.route("/download")
def download():
    name = request.args.get("name", "")
    path = os.path.join(UPLOAD_DIR, name)
    with open(path, "rb") as fh:  # PLANT: path traversal
        return fh.read()


@app.route("/user")
def user():
    username = request.args.get("u", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % username)  # PLANT: SQL injection
    return str(cur.fetchall())


@app.route("/config", methods=["POST"])
def config():
    data = yaml.load(request.data, Loader=yaml.Loader)  # PLANT: unsafe yaml
    return str(data)


@app.route("/session", methods=["POST"])
def session():
    obj = pickle.loads(request.data)  # PLANT: unsafe deserialization
    return str(obj)


if __name__ == "__main__":
    app.run()
