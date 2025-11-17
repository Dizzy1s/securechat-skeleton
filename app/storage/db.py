import json
import base64
import hashlib
import os

DB_PATH = "storage/users.json"

def load_db():
    if not os.path.exists(DB_PATH):
        return {}
    with open(DB_PATH, "r") as f:
        return json.load(f)

def save_db(db):
    os.makedirs("storage", exist_ok=True)
    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=2)

def register_user(email, username, salt_b64, pwd_hash_b64, cert_fingerprint):
    db = load_db()
    db[email] = {
        "username": username,
        "salt": salt_b64,
        "pwd_hash": pwd_hash_b64,
        "cert_fingerprint": cert_fingerprint
    }
    
    save_db(db)

def verify_login(email, pwd_hash_b64, cert_fingerprint):
    db = load_db()
    user = db.get(email)
    if not user:
        return False
    return (user["pwd_hash"] == pwd_hash_b64 and
            user["cert_fingerprint"] == cert_fingerprint)