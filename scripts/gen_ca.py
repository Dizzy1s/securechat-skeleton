# scripts/gen_ca.py
import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

OUT_DIR = "certs"
os.makedirs(OUT_DIR, exist_ok=True)

utc = datetime.timezone.utc

# Generate CA private key
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

with open(os.path.join(OUT_DIR, "ca_key.pem"), "wb") as f:
    f.write(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

# Build CA certificate
subject = issuer = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChatRoot"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"SecureChat Root CA"),
    ]
)

now = datetime.datetime.now(utc)

ca_cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(days=1))
    .not_valid_after(now + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(private_key=ca_key, algorithm=hashes.SHA256())
)

with open(os.path.join(OUT_DIR, "ca_cert.pem"), "wb") as f:
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

print("CA created:")
print(" - certs/ca_key.pem")
print(" - certs/ca_cert.pem")
