import socket
import threading
import json
import time
import base64
import os
from app.common import protocol
from app.crypto.dh import (
    generate_parameters, generate_private_key,
    public_int_from_private, derive_aes16_from_shared
)
from app.crypto.aes import aes_decrypt_bytes
from app.crypto.sign import load_privkey, load_pubkey_from_cert_bytes, rsa_verify_b64
from app.crypto.pki import verify_cert_signed_by_ca
from app.common.utils import read_pem
from app.storage.db import create_user, get_user
from app.storage.transcript import append_entry, create_session_receipt

# === Certificates & Config ===
CA_CERT = read_pem("certs/ca_cert.pem")
SERVER_KEY_PATH = "certs/server_key.pem"
SERVER_CERT_PEM = read_pem("certs/server_cert.pem")

HOST = "0.0.0.0"
PORT = 9000

# Safe DB init
if not os.getenv("DB_INITIALIZED"):
    from app.storage.db import init_schema
    try:
        init_schema()
        print("[+] DB schema ensured")
        os.environ["DB_INITIALIZED"] = "1"
    except Exception as e:
        if "already exists" not in str(e).lower():
            raise

server_priv = load_privkey(SERVER_KEY_PATH)


def handle_conn(conn, addr):
    try:
        print(f"New connection from {addr}")

        # 1. Client Hello + Cert Verification
        data = conn.recv(200000)
        if not data:
            return
        hello = json.loads(data.decode())
        client_cert_pem = hello.get("client_cert", "").encode()

        if not verify_cert_signed_by_ca(client_cert_pem, CA_CERT):
            conn.send(json.dumps({"type": protocol.MSG_TYPE_ERR, "msg": "invalid client cert"}).encode())
            conn.close()
            return

        conn.send(json.dumps({
            "type": protocol.MSG_TYPE_SERVER_HELLO,
            "server_cert": SERVER_CERT_PEM.decode()
        }).encode())

        # 2. Auth DH Exchange
        params = generate_parameters()
        priv = generate_private_key(params)
        B = public_int_from_private(priv)

        data = conn.recv(65536)
        obj = json.loads(data.decode())
        if obj.get("type") != protocol.MSG_TYPE_DH_CLIENT:
            return
        A = int(obj["A"])
        conn.send(json.dumps({"type": protocol.MSG_TYPE_DH_SERVER, "B": str(B)}).encode())

        # CRITICAL: Correct order — my_private, their_public_int
        auth_key = derive_aes16_from_shared(priv, A)

        # 3. Encrypted Auth Message
        data = conn.recv(300000)
        if not data:
            return
        payload = json.loads(data.decode())

        if payload.get("type") != protocol.MSG_TYPE_ENCRYPTED:
            return

        try:
            pt = aes_decrypt_bytes(auth_key, payload["iv"], payload["ct"])
            auth_msg = json.loads(pt.decode())
        except Exception as e:
            print(f"[{addr}] Auth decryption failed: {e}")
            conn.send(json.dumps({"type": protocol.MSG_TYPE_ERR, "msg": "decrypt fail"}).encode())
            conn.close()
            return

        # Handle Register / Login
        if auth_msg.get("type") == protocol.MSG_TYPE_REGISTER:
            success = create_user(auth_msg["email"], auth_msg["username"], auth_msg["pwd_plain"])
            resp = {"type": protocol.MSG_TYPE_OK, "msg": "registered"} if success else \
                   {"type": protocol.MSG_TYPE_ERR, "msg": "user exists"}
            conn.send(json.dumps(resp).encode())

        elif auth_msg.get("type") == protocol.MSG_TYPE_LOGIN:
            user = get_user(auth_msg["email"])
            if not user:
                conn.send(json.dumps({"type": protocol.MSG_TYPE_ERR, "msg": "no-such-user"}).encode())
            else:
                username, salt, stored_hash = user
                from app.storage.db import verify_password
                if verify_password(stored_hash, salt, auth_msg["pwd_plain"]):
                    conn.send(json.dumps({"type": protocol.MSG_TYPE_OK, "msg": "login ok"}).encode())
                else:
                    conn.send(json.dumps({"type": protocol.MSG_TYPE_ERR, "msg": "bad credentials"}).encode())
        else:
            conn.close()
            return

        # 4. Session DH (Forward Secrecy)
        params = generate_parameters()
        sess_priv = generate_private_key(params)
        B2 = public_int_from_private(sess_priv)

        data = conn.recv(65536)
        obj = json.loads(data.decode())
        A2 = int(obj["A"])
        conn.send(json.dumps({"type": protocol.MSG_TYPE_DH_SERVER, "B": str(B2)}).encode())

        session_key = derive_aes16_from_shared(sess_priv, A2)

        # 5. Message Loop
        session_id = f"{int(time.time())}_{addr[1]}"
        expected_seq = 1
        client_cert_bytes = client_cert_pem

        while True:
            data = conn.recv(500000)
            if not data:
                break
            try:
                msg = json.loads(data.decode())
            except:
                break

            t = msg.get("type")

            if t == protocol.MSG_TYPE_MSG:
                seq = int(msg["seqno"])
                ts = int(msg["ts"])
                iv = msg["iv"]
                ct = msg["ct"]
                sig = msg["sig"]

                # Verify signature
                import hashlib
                h = hashlib.sha256()
                h.update(str(seq).encode() + str(ts).encode() + ct.encode())
                pub = load_pubkey_from_cert_bytes(client_cert_bytes)
                if not rsa_verify_b64(pub, h.digest(), sig):
                    conn.send(json.dumps({"type": protocol.MSG_TYPE_ERR, "msg": "sig fail"}).encode())
                    continue

                pt = aes_decrypt_bytes(session_key, iv, ct)
                print(f"[{addr[0]}:{addr[1]}] {seq}: {pt.decode()}")

                append_entry(session_id, seq, ts, ct, sig, "client_cert_fp")
                expected_seq = max(expected_seq, seq + 1)
                conn.send(json.dumps({"type": protocol.MSG_TYPE_OK, "msg": "recv"}).encode())

            elif t == protocol.MSG_TYPE_RECEIPT_REQ:
                receipt = create_session_receipt(session_id, SERVER_KEY_PATH, 1, expected_seq - 1)
                conn.send(json.dumps({"type": protocol.MSG_TYPE_RECEIPT, **receipt}).encode())

            elif t == protocol.MSG_TYPE_CLOSE:
                break

    except Exception as e:
        print(f"Connection error from {addr}: {e}")
    finally:
        conn.close()


def start():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(8)
    print(f"SecureChat Server listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_conn, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    start()