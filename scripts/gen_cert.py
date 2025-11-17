# scripts/gen_cert.py
import argparse
import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

OUT_DIR = "certs"
os.makedirs(OUT_DIR, exist_ok=True)
utc = datetime.timezone.utc

# -------------------------------
# CLI arguments
# -------------------------------
parser = argparse.ArgumentParser(description="Generate client/server certificate signed by local CA")
parser.add_argument("--cn", required=True, help="Common Name (e.g. server.local or client.local)")
parser.add_argument("--out", required=True, help="Output prefix (e.g. certs/server or certs/client)")
args = parser.parse_args()

cn = args.cn
out_prefix = args.out          # e.g. "certs/server"  → will create certs/server_key.pem & certs/server_cert.pem
os.makedirs(os.path.dirname(out_prefix), exist_ok=True)

# -------------------------------
# Load CA
# -------------------------------
ca_key_path = os.path.join(OUT_DIR, "ca_key.pem")
ca_cert_path = os.path.join(OUT_DIR, "ca_cert.pem")

with open(ca_key_path, "rb") as f:
    ca_key = load_pem_private_key(f.read(), password=None)

with open(ca_cert_path, "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

# -------------------------------
# Generate entity key
# -------------------------------
entity_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

key_path = f"{out_prefix}_key.pem"
cert_path = f"{out_prefix}_cert.pem"

with open(key_path, "wb") as f:
    f.write(
        entity_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

# -------------------------------
# Build certificate
# -------------------------------
subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
    x509.NameAttribute(NameOID.COMMON_NAME, cn),
])

now = datetime.datetime.now(utc)

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(ca_cert.subject)
    .public_key(entity_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([x509.DNSName(cn)]),
        critical=False,
    )
    .sign(private_key=ca_key, algorithm=hashes.SHA256())
)

with open(cert_path, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("Certificate generated successfully!")
print(f"   Private key : {key_path}")
print(f"   Certificate : {cert_path}")