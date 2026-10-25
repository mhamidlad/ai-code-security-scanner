"""Vulnerable Python code — for scanner testing and demonstration."""

import os
import pickle
import hashlib
import random
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)

DEBUG = True

# PY001: SQL Injection
def get_user_by_email(email):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE email = '" + email + "'"
    cursor.execute(query)
    return cursor.fetchone()

# PY001: SQL Injection (f-string)
def get_user_by_id(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")


# PY002: Command Injection
def ping_host(host):
    os.system("ping " + host)

def ping_host2(host):
    os.system(f"ping {host}")

def run_command(user_input):
    os.popen("nslookup " + user_input)

def run_subprocess(user_input):
    subprocess.run(f"echo {user_input}", shell=True)


# PY003: Hardcoded Secrets
API_KEY = "FAKE_LIVE_KEY_1234567890abcdefghijklmnopqrstuvwxyz"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
PASSWORD = "MySecretPassword123"
github_token = "FAKE_GITHUB_TOKEN_1234567890abcdefghijklmnopqrstuvwxyz1234567890"

DB_URL = "postgres://admin:SuperSecret123@db.internal:5432/myapp"

# PY004: Unsafe Deserialization
def load_session(data):
    return pickle.loads(data)

def load_config(yaml_string):
    import yaml
    return yaml.load(yaml_string)  # Missing Loader=safe

def eval_input(user_expression):
    eval(request.args.get("expression"))


# PY005: Weak Password Hashing
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def hash_password_sha1(password):
    return hashlib.sha1(password.encode()).hexdigest()

def check_password(input_password, stored_password):
    return input_password == stored_password


# PY006: Path Traversal
def read_file(filename):
    return open(filename).read()

def get_file_path(user_input):
    return os.path.join("/app/uploads", user_input)


# PY007: XSS
def render_greeting(name):
    return render_template_string(f"<h1>Hello {name}</h1>")

def render_response():
    from django.http import HttpResponse
    return HttpResponse(request.GET.get("content"))

# PY008: SSRF
def fetch_url():
    import requests
    return requests.get(request.args.get("url"))

# PY009: Insecure Randomness
def generate_token():
    return random.choice("abcdefghijklmnopqrstuvwxyz0123456789")

def generate_session_id():
    return str(random.randint(100000, 999999))
