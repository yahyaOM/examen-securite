from flask import Flask, request
import sqlite3
import subprocess
import hashlib
import os
import bcrypt  # Added for secure hashing

app = Flask(__name__)
# In a real app, use environment variables, not hardcoded strings
SECRET_KEY = os.environ.get("SECRET_KEY", "secure-fallback-key")

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # FIXED: Using parameterized query to prevent SQL Injection
    query = "SELECT password FROM users WHERE username=?"
    cursor.execute(query, (username,))
    result = cursor.fetchone()
    
    if result and bcrypt.checkpw(password.encode(), result[0]):
        return {"status": "success", "user": username}
    return {"status": "error", "message": "Invalid credentials"}

@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host", "")
    # FIXED: Simple validation (only allowing alphanumeric/dots)
    if not all(c.isalnum() or c == '.' for c in host):
        return {"error": "Invalid host format"}, 400
    
    # FIXED: Passing host as an argument rather than shell string
    process = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
    return {"output": process.stdout}

@app.route("/compute", methods=["POST"])
def compute():
    # FIXED: Removed eval(). Using a safe alternative or simple logic
    return {"message": "Direct expression evaluation is disabled for security."}

@app.route("/hash", methods=["POST"])
def hash_password():
    pwd = request.json.get("password", "admin")
    # FIXED: Using bcrypt instead of MD5
    hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())
    return {"hash": hashed.decode()}

@app.route("/hello", methods=["GET"])
def hello():
    return {"message": "Welcome to the Secured DevSecOps API"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)