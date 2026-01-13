import os
import subprocess
import hashlib
from flask import Flask, request, render_template_string

app = Flask(__name__)

# CONFIGURATION SÉCURISÉE
# Récupération des secrets via variables d'environnement
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default-key-for-dev')
ADMIN_HASH = os.environ.get('ADMIN_HASH', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92')

def hash_password(password):
    # Utilisation de SHA-256 (Robuste)
    return hashlib.sha256(password.encode()).hexdigest()

@app.route("/login")
def login():
    username = request.args.get("username")
    password = request.args.get("password")
    if not username or not password:
        return "Missing credentials", 400
    
    if username == "admin" and hash_password(password) == ADMIN_HASH:
        return "Logged in (Securely)"
    return "Invalid credentials", 403

@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    # Validation stricte de l'entrée (Anti-injection)
    if not all(c.isalnum() or c == '.' for c in host):
        return "Invalid host format", 400

    # Commande sécurisée sans shell
    cmd = ["ping", "-c", "1", host] if os.name != 'nt' else ["ping", "-n", "1", host]
    try:
        subprocess.run(cmd, capture_output=True, shell=False, timeout=5)
        return "Ping successful"
    except Exception:
        return "Ping error"

if __name__ == "__main__":
    # DEBUG=FALSE EST OBLIGATOIRE POUR LA PIPELINE
    app.run(host='0.0.0.0', port=5000, debug=False)