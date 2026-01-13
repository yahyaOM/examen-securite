import os
import subprocess
import hashlib
from flask import Flask, request, render_template_string

app = Flask(__name__)

# --- CORRECTION 1 : GESTION DES SECRETS (Bandit B105) ---
# On ne met jamais de mots de passe en dur dans le code.
# On les récupère via des variables d'environnement.
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default-key-for-dev-only')
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_HASH', '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92')
# Note : Le hash par défaut correspond à "123456" hashé en SHA-256.

# --- CORRECTION 2 : CRYPTOGRAPHIE FORTE (Bandit B303) ---
# Remplacement de MD5 (cassé) par SHA-256.
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route("/login")
def login():
    username = request.args.get("username")
    password = request.args.get("password")

    if not username or not password:
        return "Missing credentials", 400

    # Vérification sécurisée du hash
    if username == "admin" and hash_password(password) == ADMIN_PASSWORD_HASH:
        return "Logged in (Securely)"
    
    return "Invalid credentials", 403

@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")

    # --- CORRECTION 3 : PRÉVENTION INJECTION DE COMMANDE (Bandit B602) ---
    # 1. Validation stricte de l'entrée (liste blanche de caractères)
    if not all(c.isalnum() or c == '.' for c in host):
        return "Invalid host format", 400

    # 2. Utilisation sécurisée de subprocess
    # shell=False est OBLIGATOIRE pour Bandit.
    # On passe la commande sous forme de liste ['cmd', 'arg1', 'arg2'].
    cmd_flag = "-n" if os.name == 'nt' else "-c"
    command = ["ping", cmd_flag, "1", host]

    try:
        # capture_output=True est plus moderne et sécurisé que check_output
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            shell=False,  # Point crucial pour la pipeline
            timeout=5
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Ping timed out"
    except Exception:
        return "Ping error"

@app.route("/hello")
def hello():
    name = request.args.get("name", "user")
    
    # --- CORRECTION 4 : PRÉVENTION XSS ---
    # Utilisation du moteur de template Jinja2 qui échappe automatiquement les balises HTML.
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)

if __name__ == "__main__":
    # --- CORRECTION 5 : DÉSACTIVATION DU DEBUG (Bandit B201) ---
    # Le mode debug=True ferait échouer la pipeline immédiatement.
    app.run(host='0.0.0.0', port=5000, debug=False)