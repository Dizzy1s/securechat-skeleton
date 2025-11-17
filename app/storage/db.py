# app/storage/db.py
import os
import pymysql
import binascii
from app.crypto.sign import rsa_sign_b64  # not used here, but available
from hashlib import sha256

# configure via env variables or edit here for local testing
DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "127.0.0.1"),
    "user": os.environ.get("DB_USER", "root"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "db": os.environ.get("DB_NAME", "securechat"),
    "autocommit": True,
    "cursorclass": pymysql.cursors.DictCursor
}

def get_conn():
    return pymysql.connect(**DB_CONFIG)

def init_schema():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("CREATE DATABASE IF NOT EXISTS %s" % DB_CONFIG["db"])
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
      username VARCHAR(100) PRIMARY KEY,
      email VARCHAR(255),
      salt BINARY(16),
      pwd_hash CHAR(64)
    )""")
    cur.close()
    conn.close()

def create_user(email: str, username: str, password_plain: str):
    salt = os.urandom(16)
    h = sha256(salt + password_plain.encode()).hexdigest()
    conn = get_conn(); cur = conn.cursor()
    cur.execute("INSERT INTO users(username,email,salt,pwd_hash) VALUES(%s,%s,%s,%s)",
                (username, email, salt, h))
    cur.close(); conn.close()
    return True

def get_user(username: str):
    conn = get_conn(); cur = conn.cursor()
    cur.execute("SELECT username,email,salt,pwd_hash FROM users WHERE username=%s", (username,))
    r = cur.fetchone()
    cur.close(); conn.close()
    return r  # None or dict
