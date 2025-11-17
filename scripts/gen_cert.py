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

# CLI argument: --cn <common-name>
parser = argparse.ArgumentParser()
parser.add_argument("--cn", required=True, help="Common Name for certificate")
args = parser.parse_args()
cn = args.cn

# Load CA
with open(os.path.join(OUT_DIR, "ca_key.pem"), "rb") as f:
    ca_key = load_pem_private_key(f.read(), password=None)

with open(os.path.join(OUT_DIR, "ca_cert.pem"), "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

# Generate entity key (client/server)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
key_path = os.path.join(OUT_DIR, f"{cn}_key.pem")
with open(key_path, "wb") as f:
    f.write(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

# Subject
subject = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ]
)

# Time
now = datetime.datetime.now(utc)

# Build cert
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(ca_cert.subject)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=365))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
    .sign(private_key=ca_key, algorithm=hashes.SHA256())
)

cert_path = os.path.join(OUT_DIR, f"{cn}_cert.pem")
with open(cert_path, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("Certificate generated:")
print(" -", key_path)
print(" -", cert_path)
