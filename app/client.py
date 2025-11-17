import socket
import json
import time
import base64
from app.common import protocol
from app.crypto.dh import generate_parameters, generate_private_key, public_int_from_private, derive_aes16_from_shared
from app.crypto.aes import aes_encrypt_bytes, aes_decrypt_bytes
from app.crypto.sign import load_privkey, rsa_sign_b64
from app.crypto.pki import verify_cert_signed_by_ca
from app.common.utils import read_pem
from app.storage.transcript import append_entry, create_session_receipt, compute_transcript_sha256

CA_CERT = read_pem("certs/ca_cert.pem")
CLIENT_KEY_PATH = "certs/client_key.pem"
CLIENT_CERT_PEM = read_pem("certs/client_cert.pem")

HOST = "127.0.0.1"
PORT = 9000


def connect_and_run():
    s = socket.socket()
    s.connect((HOST, PORT))

    # 1) Hello with client cert
    s.send(json.dumps({
        "type": protocol.MSG_TYPE_HELLO,
        "client_cert": CLIENT_CERT_PEM.decode()
    }).encode())

    # 2) Receive server hello + verify cert
    data = s.recv(65536)
    srv = json.loads(data.decode())
    server_cert_pem = srv.get("server_cert", "").encode()
    if not verify_cert_signed_by_ca(server_cert_pem, CA_CERT):
        print("Server cert verification failed")
        s.close()
        return
    print("Server certificate OK")

    # 3) Auth DH exchange
    params = generate_parameters()
    priv = generate_private_key(params)
    A = public_int_from_private(priv)
    s.send(json.dumps({"type": protocol.MSG_TYPE_DH_CLIENT, "A": str(A)}).encode())

    data = s.recv(65536)
    resp = json.loads(data.decode())
    B = int(resp["B"])
    auth_key = derive_aes16_from_shared(priv, B)

    # 4) REGISTER (encrypted) — FIXED: base64 encode iv/ct
    reg = {
        "type": protocol.MSG_TYPE_REGISTER,
        "email": "moaz@example.com",
        "username": "moaz",
        "pwd_plain": "mypassword"
    }
    wrapped = aes_encrypt_bytes(auth_key, json.dumps(reg).encode())
    encrypted_payload = {
        "type": protocol.MSG_TYPE_ENCRYPTED,
        "iv": base64.b64encode(wrapped["iv"]).decode(),
        "ct": base64.b64encode(wrapped["ct"]).decode()
    }
    s.send(json.dumps(encrypted_payload).encode())

    resp = json.loads(s.recv(65536).decode())
    print("Auth response:", resp)

    # 5) Session DH (forward secrecy)
    params = generate_parameters()
    sess_priv = generate_private_key(params)
    A2 = public_int_from_private(sess_priv)
    s.send(json.dumps({"type": protocol.MSG_TYPE_DH_CLIENT, "A": str(A2)}).encode())

    data = s.recv(65536)
    resp = json.loads(data.decode())
    B2 = int(resp["B"])
    session_key = derive_aes16_from_shared(sess_priv, B2)

    # 6) Send 3 signed messages — FIXED: base64 encode iv/ct
    privkey = load_privkey(CLIENT_KEY_PATH)
    seq = 1
    session_id = str(int(time.time()))

    while seq <= 3:
        plaintext = f"client message {seq}".encode()
        wrapped = aes_encrypt_bytes(session_key, plaintext)
        ts = int(time.time() * 1000)

        # Sign SHA256(seq || ts || ct)
        import hashlib
        h = hashlib.sha256()
        h.update(str(seq).encode() + str(ts).encode() + wrapped["ct"])
        sig = rsa_sign_b64(privkey, h.digest())

        msg = {
            "type": protocol.MSG_TYPE_MSG,
            "seqno": seq,
            "ts": ts,
            "iv": base64.b64encode(wrapped["iv"]).decode(),
            "ct": base64.b64encode(wrapped["ct"]).decode(),
            "sig": sig
        }
        s.send(json.dumps(msg).encode())

        srv_resp = json.loads(s.recv(65536).decode())
        print("server:", srv_resp)

        append_entry(session_id, seq, ts, wrapped["ct"], sig, "server_cert_fp")
        seq += 1
        time.sleep(0.5)

    # 7) Request receipt
    s.send(json.dumps({"type": protocol.MSG_TYPE_RECEIPT_REQ}).encode())
    receipt = json.loads(s.recv(65536).decode())
    print("received receipt:", receipt)

    # 8) Generate local receipt
    local_receipt = create_session_receipt(session_id, CLIENT_KEY_PATH, 1, seq - 1)
    print("local receipt:", local_receipt)
    print("transcript_sha256:", compute_transcript_sha256(session_id))

    # 9) Close
    s.send(json.dumps({"type": protocol.MSG_TYPE_CLOSE}).encode())
    s.close()


if __name__ == "__main__":
    connect_and_run()