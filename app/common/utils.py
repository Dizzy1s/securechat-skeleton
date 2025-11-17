
import time
import base64
import hashlib
import os

def now_ms() -> int:
    """Return current time in milliseconds."""
    return int(time.time() * 1000)

def b64e(b: bytes) -> str:
    """Base64-encode bytes -> str."""
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    """Base64-decode str -> bytes."""
    return base64.b64decode(s.encode())

def sha256_hex(data: bytes) -> str:
    """Return SHA-256 hash of data as hex string."""
    return hashlib.sha256(data).hexdigest()

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT_DIR = os.path.join(ROOT, "certs")  # place certs next to app/ or adapt

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def read_pem(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()
