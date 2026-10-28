"""Deliberately vulnerable Flask app — a scan target for the pipeline.
DO NOT deploy. For local scanning/demo only.
Run:  python vulnerable_apps/vulnerable_flask_app/app.py
"""
import sqlite3

from flask import Flask, request

app = Flask(__name__)
SECRET_KEY = "hardcoded-secret-do-not-do-this"   # insecure: hardcoded secret


@app.route("/login")
def login():
    user = request.args.get("user", "")
    # insecure: SQL injection (string concatenation)
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE IF NOT EXISTS users(name text)")
    query = f"SELECT * FROM users WHERE name = '{user}'"
    conn.execute(query)
    return f"Queried: {query}"


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<p>Results for {q}</p>"       # insecure: reflected XSS


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)      # insecure: debug/dev server exposed
