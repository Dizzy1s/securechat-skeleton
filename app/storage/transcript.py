# app/storage/transcript.py
import os
import hashlib
from app.common.utils import ensure_dir
from app.crypto.sign import rsa_sign_b64, rsa_verify_b64, load_privkey, load_pubkey_from_cert_bytes

TRANSCRIPT_DIR = os.path.join(os.path.dirname(__file__), "transcripts")
ensure_dir(TRANSCRIPT_DIR)

def transcript_path(session_id: str) -> str:
    return os.path.join(TRANSCRIPT_DIR, f"transcript_{session_id}.log")

def append_entry(session_id: str, seq: int, ts: int, ct_b64: str, sig_b64: str, peer_cert_fingerprint: str):
    p = transcript_path(session_id)
    line = f"{seq}|{ts}|{ct_b64}|{sig_b64}|{peer_cert_fingerprint}\n"
    with open(p, "a", encoding="utf-8") as f:
        f.write(line)

def compute_transcript_sha256(session_id: str) -> str:
    p = transcript_path(session_id)
    if not os.path.exists(p):
        return hashlib.sha256(b"").hexdigest()
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def create_session_receipt(session_id: str, privkey_path: str, first_seq: int, last_seq: int) -> dict:
    trhash = compute_transcript_sha256(session_id)
    priv = load_privkey(privkey_path)
    sig = rsa_sign_b64(priv, trhash.encode())
    return {"first_seq": first_seq, "last_seq": last_seq, "transcript_sha256": trhash, "sig": sig}

def verify_session_receipt(receipt: dict, peer_cert_bytes: bytes) -> bool:
    pub = load_pubkey_from_cert_bytes(peer_cert_bytes)
    return rsa_verify_b64(pub, receipt["transcript_sha256"].encode(), receipt["sig"])
