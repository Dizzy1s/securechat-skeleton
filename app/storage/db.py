# app/storage/db.py
import os
import hashlib
import secrets
import mysql.connector
from mysql.connector import Error, pooling
from mysql.connector.connection import MySQLConnection
from mysql.connector.cursor import MySQLCursor
from typing import Optional, Tuple

# Default config – ONLY for local development! Never use in production without .env override
DEFAULT_CONFIG = {
    "host": "localhost",
    "port": 3306,
    "user": "scuser",
    "password": "scpass",
    "database": "securechat",
}

DB_CONFIG = {
    "host": os.getenv("DB_HOST", DEFAULT_CONFIG["host"]),
    "port": int(os.getenv("DB_PORT", DEFAULT_CONFIG["port"])),
    "user": os.getenv("DB_USER", DEFAULT_CONFIG["user"]),
    "password": os.getenv("DB_PASSWORD", DEFAULT_CONFIG["password"]),
    "database": os.getenv("DB_NAME", DEFAULT_CONFIG["database"]),
    "autocommit": True,
    "charset": "utf8mb4",
    "use_pure": True,
    "raise_on_warnings": True,
}

# Optional connection pool (great for Flask/FastAPI)
try:
    connection_pool = pooling.MySQLConnectionPool(pool_name="scp", pool_size=10, **DB_CONFIG)
except Error:
    connection_pool = None


def get_connection() -> MySQLConnection:
    """Return a connection from pool if available, otherwise create new one"""
    if connection_pool:
        return connection_pool.get_connection()
    return mysql.connector.connect(**DB_CONFIG)


def init_schema() -> None:
    """Create the users table with secure schema"""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            email       VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
            username    VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL UNIQUE,
            salt        BINARY(16) NOT NULL,
            pwd_hash    BINARY(32) NOT NULL,  -- SHA-256 raw 32 bytes
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_email (email),
            INDEX idx_username (username)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """)

    conn.commit()
    cursor.close()
    conn.close()
    print("[+] Database schema initialized (secure version)")


def create_user(email: str, username: str, password: str) -> bool:
    """Register new user with salted SHA-256 (raw bytes). Returns True on success."""
    salt = secrets.token_bytes(16)
    pwd_hash = hashlib.sha256(salt + password.encode("utf-8")).digest()  # 32 raw bytes

    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Check if email or username already taken
        cursor.execute(
            "SELECT 1 FROM users WHERE email = %s OR username = %s",
            (email.lower(), username)
        )
        if cursor.fetchone():
            return False

        cursor.execute(
            """
            INSERT INTO users (email, username, salt, pwd_hash)
            VALUES (%s, %s, %s, %s)
            """,
            (email.lower(), username, salt, pwd_hash)
        )

        conn.commit()
        print(f"[+] User registered: {username} ({email})")
        return True

    except Error as e:
        print(f"[-] DB Error in create_user: {e}")
        return False

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


def get_user(email: str) -> Optional[Tuple[str, bytes, bytes]]:
    """
    Retrieve user by email.
    Returns (username, salt_bytes, pwd_hash_bytes) or None
    """
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT username, salt, pwd_hash FROM users WHERE email = %s",
            (email.lower(),)
        )
        result = cursor.fetchone()
        if result:
            return result[0], result[1], result[2]  # username, salt, hash
        return None

    except Error as e:
        print(f"[-] DB Error in get_user: {e}")
        return None

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


def verify_password(stored_hash: bytes, salt: bytes, password: str) -> bool:
    """Constant-time password verification"""
    computed = hashlib.sha256(salt + password.encode("utf-8")).digest()
    return secrets.compare_digest(computed, stored_hash)


# CLI support
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SecureChat DB Helper")
    parser.add_argument("--init", action="store_true", help="Initialize database schema")
    args = parser.parse_args()

    if args.init:
        init_schema()