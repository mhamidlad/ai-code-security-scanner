"""Secure Python code — demonstrates proper security practices."""

import os
import sqlite3
import secrets
import hashlib
import hmac
import json
import subprocess
from pathlib import Path

from flask import Flask, request, escape

app = Flask(__name__)

DEBUG = os.environ.get("FLASK_DEBUG", "False").lower() == "true"

# PY001: Secure SQL — parameterized queries
def get_user_by_email(email):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    return cursor.fetchone()

# PY001: Secure SQL — ORM approach
def get_user_by_id(user_id):
    # Using SQLAlchemy ORM
    return User.query.filter_by(id=user_id).first()

# PY002: Secure command execution — no shell
def ping_host(host):
    # Validate host
    if not host.replace(".", "").replace("-", "").isalnum():
        raise ValueError("Invalid hostname")
    result = subprocess.run(
        ["ping", "-c", "4", host],
        capture_output=True,
        text=True,
        shell=False,
    )
    return result.stdout

# PY003: Secrets in environment variables
API_KEY = os.environ.get("API_KEY")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
DB_URL = os.environ.get("DATABASE_URL")

# PY004: Safe deserialization
def load_session(data):
    return json.loads(data)

def load_config(yaml_string):
    import yaml
    return yaml.safe_load(yaml_string)

# PY005: Secure password hashing with bcrypt
import bcrypt

def hash_password(password):
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt)

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

# PY006: Secure file access
ALLOWED_DIR = Path("/app/uploads").resolve()

def read_file(filename):
    filepath = (ALLOWED_DIR / filename).resolve()
    if not str(filepath).startswith(str(ALLOWED_DIR)):
        raise ValueError("Path traversal detected")
    return filepath.read_text()

# PY007: XSS prevention — escaped output
def render_greeting(name):
    return f"<h1>Hello {escape(name)}</h1>"

# PY008: SSRF prevention — allowlist
ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}

def fetch_url(url):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")
    import requests
    return requests.get(url, timeout=5)

# PY009: Secure randomness
def generate_token():
    return secrets.token_hex(32)

def generate_session_id():
    return secrets.token_urlsafe(32)
