import os
import subprocess
import hashlib
from flask import Flask, request, render_template_string

app = Flask(__name__)

# CORRECTION : Secrets via variables d'environnement
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'cle-secrete-par-defaut')
ADMIN_HASH = os.environ.get('ADMIN_HASH', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92')

def hash_password(password):
    # CORRECTION : SHA-256 au lieu de MD5
    return hashlib.sha256(password.encode()).hexdigest()

@app.route("/login")
def login():
    username = request.args.get("username")
    password = request.args.get("password")
    if not username or not password:
        return "Missing credentials", 400
    if username == "admin" and hash_password(password) == ADMIN_HASH:
        return "Logged in"
    return "Invalid credentials", 403

@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # CORRECTION : Validation de l'entrée pour éviter l'injection
    if not all(c.isalnum() or c == '.' for c in host):
        return "Invalid host", 400
    
    # CORRECTION : shell=False pour éviter l'injection de commande
    cmd = ["ping", "-c", "1", host] if os.name != 'nt' else ["ping", "-n", "1", host]
    try:
        subprocess.run(cmd, capture_output=True, shell=False, timeout=5)
        return "Ping réussi"
    except Exception:
        return "Ping error"

if __name__ == "__main__":
    # CORRECTION : Debug désactivé pour la prod
    app.run(host='0.0.0.0', port=5000, debug=False)