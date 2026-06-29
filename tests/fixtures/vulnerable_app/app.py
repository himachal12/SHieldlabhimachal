"""
INTENTIONALLY VULNERABLE test Flask app.
Used ONLY to test ShieldLabs scanner accuracy. Never deploy this.
Each vulnerability is marked with a comment for our own reference.
"""

from flask import Flask, request, redirect
import sqlite3
import hashlib
import os
import pickle

app = Flask(__name__)

# VULN: Hardcoded secret
API_KEY = "hardcoded-secret-for-testing-1234567890abcdef"
DB_PASSWORD = "admin123"


def get_db_connection():
    conn = sqlite3.connect('users.db')
    return conn


# VULN: SQL Injection (string concatenation in query)
@app.route('/search')
def search_user():
    user_id = request.args.get('id')
    conn = get_db_connection()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor = conn.execute(query)
    result = cursor.fetchall()
    return str(result)


# VULN: Weak password hashing (MD5, no salt)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    hashed = hash_password(password)
    conn = get_db_connection()
    conn.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{hashed}')")
    return "registered"


# VULN: Command injection
@app.route('/ping')
def ping_host():
    host = request.args.get('host')
    result = os.system(f"ping -c 1 {host}")
    return str(result)


# VULN: Insecure deserialization
@app.route('/load')
def load_session():
    data = request.args.get('data')
    obj = pickle.loads(data.encode())
    return str(obj)


# VULN: Unvalidated redirect
@app.route('/redirect')
def redirect_user():
    url = request.args.get('url')
    return redirect(url)


if __name__ == '__main__':
    app.run(debug=True)  # VULN: debug mode enabled in production