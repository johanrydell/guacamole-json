import logging
import sys
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


def generate_self_signed_cert(config):
    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, config["CERT_COUNTRY"]),
                x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME, config["CERT_STATE"]
                ),
                x509.NameAttribute(NameOID.LOCALITY_NAME, config["CERT_LOCALITY"]),
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME, config["CERT_ORGANIZATION"]
                ),
                x509.NameAttribute(NameOID.COMMON_NAME, config["CERT_COMMON_NAME"]),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(
                datetime.now(timezone.utc)
                + timedelta(days=int(config["CERT_VALIDITY_DAYS"]))
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(config["CERT_COMMON_NAME"])]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        return cert_pem, key_pem
    except Exception as e:
        logger.error(f"Failed to generate self-signed certificate: {e}")
        sys.exit(1)
