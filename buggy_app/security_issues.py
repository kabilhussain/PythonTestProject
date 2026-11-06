"""Security vulnerabilities (SAST targets: SonarQube, Bandit, Semgrep, Ruff S-rules)."""
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess
import tempfile
import xml.etree.ElementTree as ET

import yaml  # noqa: F401  (may be missing -> import error detection)

# BUG S1: hard-coded credentials / secrets
DB_PASSWORD = "SuperSecret123!"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"


def get_user(conn: sqlite3.Connection, username):
    # BUG S2: SQL injection via string formatting
    query = "SELECT * FROM users WHERE name = '%s'" % username
    return conn.execute(query).fetchall()


def get_user_fstring(conn, user_id):
    # BUG S3: SQL injection via f-string
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE id = {user_id}")
    conn.commit()


def ping_host(host):
    # BUG S4: OS command injection (shell=True with user input)
    return subprocess.check_output("ping -c 1 " + host, shell=True)


def list_dir(path):
    # BUG S5: command injection through os.system
    os.system("ls -la " + path)


def evaluate_expression(expr):
    # BUG S6: arbitrary code execution through eval
    return eval(expr)


def run_code(code):
    # BUG S7: exec of untrusted input
    exec(code)


def load_session(data: bytes):
    # BUG S8: insecure deserialization
    return pickle.loads(data)


def load_config(text):
    # BUG S9: unsafe YAML load
    return yaml.load(text)


def hash_password(password):
    # BUG S10: weak hashing algorithm, no salt
    return hashlib.md5(password.encode()).hexdigest()


def hash_token(token):
    # BUG S11: SHA1 is also weak for security purposes
    return hashlib.sha1(token.encode()).hexdigest()


def generate_reset_token():
    # BUG S12: non-cryptographic PRNG for a security token
    return "".join(str(random.randint(0, 9)) for _ in range(6))


def write_temp(data):
    # BUG S13: insecure temp file (race condition)
    name = tempfile.mktemp()
    with open(name, "w") as fh:
        fh.write(data)
    return name


def write_world_writable(path):
    # BUG S14: overly permissive file permissions
    with open(path, "w") as fh:
        fh.write("secret")
    os.chmod(path, 0o777)


def parse_xml(xml_string):
    # BUG S15: XML parsing vulnerable to XXE / billion laughs
    return ET.fromstring(xml_string)


def read_user_file(filename):
    # BUG S16: path traversal
    base = "/var/app/uploads/"
    with open(base + filename) as fh:
        return fh.read()


def fetch(url):
    import requests  # noqa: PLC0415

    # BUG S17: TLS verification disabled, no timeout
    return requests.get(url, verify=False)


def bind_all():
    import socket  # noqa: PLC0415

    s = socket.socket()
    # BUG S18: binding to all interfaces
    s.bind(("0.0.0.0", 8080))
    return s


def check_admin(user):
    # BUG S19: assert used for security check (stripped with -O)
    assert user.is_admin, "not admin"
    return True


def flask_app():
    from flask import Flask  # noqa: PLC0415

    app = Flask(__name__)
    # BUG S20: debug mode enabled
    app.run(debug=True, host="0.0.0.0")
