# app/storage/db.py
import os
import hashlib
import secrets
import mysql.connector
from mysql.connector import Error
from typing import Optional, Tuple

# Load config from .env (or fallback)
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER", "scuser"),
    "password": os.getenv("DB_PASSWORD", "scpass"),
    "database": os.getenv("DB_NAME", "securechat"),
}

def get_connection():
    return mysql.connector.connect(**DB_CONFIG)

def init_schema():
    """Create the users table if it doesn't exist"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email VARCHAR(255) PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            salt VARBINARY(16) NOT NULL,
            pwd_hash CHAR(64) NOT NULL
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()
    print("[+] Database schema initialized")

def create_user(email: str, username: str, password: str) -> bool:
    """
    Register a new user with salted SHA-256 password
    Returns True if user created, False if email/username already exists
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Check if user already exists
        cursor.execute("SELECT 1 FROM users WHERE email = %s OR username = %s", (email, username))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return False

        # Generate 16-byte random salt
        salt = secrets.token_bytes(16)

        # pwd_hash = hex(SHA256(salt || password))
        hash_input = salt + password.encode('utf-8')
        pwd_hash = hashlib.sha256(hash_input).hexdigest()

        cursor.execute("""
            INSERT INTO users (email, username, salt, pwd_hash)
            VALUES (%s, %s, %s, %s)
        """, (email, username, salt, pwd_hash))

        conn.commit()
        cursor.close()
        conn.close()
        print(f"[+] User registered: {username} ({email})")
        return True

    except Error as e:
        print(f"[-] DB Error in create_user: {e}")
        return False

def get_user(email: str) -> Optional[Tuple[str, bytes, str]]:
    """
    Retrieve user record by email
    Returns (username, salt, pwd_hash) or None
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username, salt, pwd_hash FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        if result:
            return result[0], result[1], result[2]  # username, salt (bytes), pwd_hash (str)
        return None
    except Error as e:
        print(f"[-] DB Error in get_user: {e}")
        return None

def verify_password(stored_hash: str, salt: bytes, password: str) -> bool:
    """
    Constant-time password verification
    """
    hash_input = salt + password.encode('utf-8')
    computed = hashlib.sha256(hash_input).hexdigest()
    # Constant-time comparison
    return secrets.compare_digest(computed.encode(), stored_hash.encode())

# CLI support: python -m app.storage.db --init
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--init", action="store_true", help="Initialize database schema")
    args = parser.parse_args()
    if args.init:
        init_schema()