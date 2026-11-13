"""Deliberately vulnerable sample for CodeSift tests. Never deploy."""

import hashlib
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run():
    cmd = request.args.get("cmd", "")
    # REAL: command injection from a request parameter
    return subprocess.check_output("echo " + cmd, shell=True)


@app.route("/calc")
def calc():
    # REAL: eval of user input
    return str(eval(request.args.get("expr", "1")))


@app.route("/load", methods=["POST"])
def load():
    # REAL: unpickling request data
    return str(pickle.loads(request.data))


@app.route("/user")
def user():
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    # REAL: SQL injection via string formatting
    rows = conn.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()
    return str(rows)


def parse_config(text: str):
    # REAL: unsafe YAML loader
    return yaml.load(text, Loader=yaml.Loader)


def fetch_status(url: str) -> int:
    # REAL: TLS verification disabled
    return requests.get(url, verify=False, timeout=5).status_code


def list_home() -> bytes:
    # FALSE POSITIVE: fixed argument list, no shell, no user input
    return subprocess.check_output(["ls", "-la", "/home"])


def cache_key(data: bytes) -> str:
    # FALSE POSITIVE: md5 used as a non-security cache key
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


if __name__ == "__main__":
    # REAL: debug mode exposes the Werkzeug debugger
    app.run(debug=True, host="0.0.0.0")
