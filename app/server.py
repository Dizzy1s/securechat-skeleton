# app/server.py
import socket, threading, json, time
from app.common import protocol
from app.crypto.dh import generate_parameters, generate_private_key, public_int_from_private, derive_aes16_from_shared
from app.crypto.aes import aes_decrypt_bytes, aes_encrypt_bytes
from app.crypto.sign import load_privkey, load_pubkey_from_cert_bytes, rsa_verify_b64, rsa_sign_b64
from app.crypto.pki import verify_cert_signed_by_ca, cert_common_name
from app.common.utils import read_pem
from app.storage.db import create_user, get_user, init_schema
from app.storage.transcript import append_entry, create_session_receipt, compute_transcript_sha256
from app.common.utils import read_pem
import os

CA_CERT = read_pem("certs/ca_cert.pem")
SERVER_KEY_PATH = "certs/server_key.pem"
SERVER_CERT_PEM = read_pem("certs/server_cert.pem")

HOST = "0.0.0.0"; PORT = 9000

# Only run schema init on first start or when --init flag is used
if not os.getenv("DB_INITIALIZED"):
    try:
        init_schema()
        print("[+] DB schema ensured")
        os.environ["DB_INITIALIZED"] = "1"  # Mark as done in this process
    except Exception as e:
        if "already exists" not in str(e):
            raise  # Re-raise if it's not the "already exists" error

server_priv = load_privkey(SERVER_KEY_PATH)

def handle_conn(conn, addr):
    try:
        data = conn.recv(200000)
        hello = json.loads(data.decode())
        client_cert_pem = hello.get("client_cert").encode()
        if not verify_cert_signed_by_ca(client_cert_pem, CA_CERT):
            conn.send(json.dumps({"type": protocol.MSG_TYPE_ERR, "msg": "invalid client cert"}).encode())
            conn.close(); return
        # send server hello
        conn.send(json.dumps({"type": protocol.MSG_TYPE_SERVER_HELLO, "server_cert": SERVER_CERT_PEM.decode()}).encode())

        # DH for auth
        params = generate_parameters()
        priv = generate_private_key(params)
        B = public_int_from_private(priv)
        # expect client's A
        data = conn.recv(65536); obj = json.loads(data.decode())
        if obj.get("type") != protocol.MSG_TYPE_DH_CLIENT:
            conn.close(); return
        A = int(obj["A"])
        conn.send(json.dumps({"type": protocol.MSG_TYPE_DH_SERVER, "B": str(B)}).encode())
        key16 = derive_aes16_from_shared(priv, A)

        data = conn.recv(300000)
        payload = json.loads(data.decode())
        if payload.get("type") == protocol.MSG_TYPE_ENCRYPTED:
            pt = aes_decrypt_bytes(key16, payload["iv"], payload["ct"])
            j = json.loads(pt.decode())
            if j.get("type") == protocol.MSG_TYPE_REGISTER:
                create_user(j["email"], j["username"], j["pwd_plain"])
                conn.send(json.dumps({"type": protocol.MSG_TYPE_OK, "msg": "registered"}).encode())
            elif j.get("type") == protocol.MSG_TYPE_LOGIN:
                u = get_user(j["username"])
                if not u:
                    conn.send(json.dumps({"type": protocol.MSG_TYPE_ERR, "msg": "no-such-user"}).encode())
                else:
                    # compare hashes
                    import hashlib
                    salt = u["salt"]
                    recomputed = hashlib.sha256(salt + j["pwd_plain"].encode()).hexdigest()
                    if recomputed == u["pwd_hash"]:
                        conn.send(json.dumps({"type": protocol.MSG_TYPE_OK, "msg": "login ok"}).encode())
                    else:
                        conn.send(json.dumps({"type": protocol.MSG_TYPE_ERR, "msg": "bad credentials"}).encode())
        else:
            conn.send(json.dumps({"type": protocol.MSG_TYPE_ERR, "msg": "bad auth flow"}).encode()); conn.close(); return

        # session DH
        params = generate_parameters()
        sess_priv = generate_private_key(params)
        B2 = public_int_from_private(sess_priv)
        data = conn.recv(65536); obj = json.loads(data.decode()); A2 = int(obj["A"])
        conn.send(json.dumps({"type": protocol.MSG_TYPE_DH_SERVER, "B": str(B2)}).encode())
        session_key = derive_aes16_from_shared(sess_priv, A2)

        # message loop
        session_id = str(int(time.time())) + "_" + str(addr[1])
        expected_seq = 1
        client_cert_bytes = client_cert_pem
        while True:
            data = conn.recv(500000)
            if not data:
                break
            msg = json.loads(data.decode())
            t = msg.get("type")
            if t == protocol.MSG_TYPE_MSG:
                seq = int(msg["seqno"]); ts = int(msg["ts"]); iv = msg["iv"]; ct = msg["ct"]; sig = msg["sig"]
                # verify signature over sha256(seq||ts||ct)
                import hashlib
                h = hashlib.sha256()
                h.update(str(seq).encode() + str(ts).encode() + ct.encode())
                pub = load_pubkey_from_cert_bytes(client_cert_bytes)
                if not rsa_verify_b64(pub, h.digest(), sig):
                    conn.send(json.dumps({"type": protocol.MSG_TYPE_ERR, "msg": "sig fail"}).encode()); continue
                # decrypt
                pt = aes_decrypt_bytes(session_key, iv, ct)
                print(f"[{addr}] {seq}: {pt.decode()}")
                append_entry(session_id, seq, ts, ct, sig, "client_cert_fp")
                expected_seq = max(expected_seq, seq+1)
                conn.send(json.dumps({"type": protocol.MSG_TYPE_OK, "msg": "recv"}).encode())
            elif t == protocol.MSG_TYPE_RECEIPT_REQ:
                # compute transcript hash and sign
                receipt = create_session_receipt(session_id, SERVER_KEY_PATH, 1, expected_seq-1)
                conn.send(json.dumps({"type": protocol.MSG_TYPE_RECEIPT, **receipt}).encode())
            elif t == protocol.MSG_TYPE_CLOSE:
                break
            else:
                conn.send(json.dumps({"type": protocol.MSG_TYPE_ERR, "msg": "unknown"}).encode())
    except Exception as e:
        print("conn error", e)
    finally:
        conn.close()

def start():
    s = socket.socket()
    s.bind((HOST, PORT))
    s.listen(8)
    print("listening", HOST, PORT)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_conn, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start()
