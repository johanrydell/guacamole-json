import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


class CertificateError(Exception):
    """Custom exception for certificate generation errors."""


def create_key_pair() -> rsa.RSAPrivateKey:
    """
    Generates an RSA private key.

    Returns:
        rsa.RSAPrivateKey: The generated RSA private key.
    """
    logger.debug("Generating RSA private key...")
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def create_certificate_subject(config: Dict[str, str]) -> x509.Name:
    """
    Creates an X.509 certificate subject and issuer using the provided configuration.

    Args:
        config (Dict[str, str]): Configuration for the certificate attributes.

    Returns:
        x509.Name: The subject/issuer for the certificate.
    """
    logger.debug("Creating certificate subject and issuer...")
    try:
        return x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COUNTRY_NAME, config.get("CERT_COUNTRY", "US")
                ),
                x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME, config.get("CERT_STATE", "Unknown")
                ),
                x509.NameAttribute(
                    NameOID.LOCALITY_NAME, config.get("CERT_LOCALITY", "Unknown")
                ),
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME,
                    config.get("CERT_ORGANIZATION", "Default Org"),
                ),
                x509.NameAttribute(
                    NameOID.COMMON_NAME, config.get("CERT_COMMON_NAME", "localhost")
                ),
            ]
        )
    except Exception as e:
        raise CertificateError(f"Failed to create certificate subject: {e}")


def create_self_signed_cert(
    key: rsa.RSAPrivateKey, subject: x509.Name, config: Dict[str, str]
) -> x509.Certificate:
    """
    Generates a self-signed X.509 certificate.

    Args:
        key (rsa.RSAPrivateKey): The private key for signing the certificate.
        subject (x509.Name): The subject/issuer of the certificate.
        config (Dict[str, str]): Configuration for certificate validity and attributes.

    Returns:
        x509.Certificate: The generated self-signed certificate.
    """
    logger.debug("Generating self-signed certificate...")
    validity_days = int(config.get("CERT_VALIDITY_DAYS", 365))
    try:
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName(config.get("CERT_COMMON_NAME", "localhost"))]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
    except Exception as e:
        raise CertificateError(f"Failed to generate self-signed certificate: {e}")


def generate_self_signed_cert(config: Dict[str, str]) -> Tuple[bytes, bytes]:
    """
    Generates a self-signed certificate and its private key.

    Args:
        config (Dict[str, str]): Configuration for the certificate attributes.

    Returns:
        Tuple[bytes, bytes]: The certificate and private key in PEM format.

    Raises:
        CertificateError: If the certificate generation fails.
    """
    try:
        logger.info("Starting self-signed certificate generation...")
        key = create_key_pair()
        subject = create_certificate_subject(config)
        cert = create_self_signed_cert(key, subject, config)

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )

        logger.info("Self-signed certificate generation completed successfully.")
        return cert_pem, key_pem
    except CertificateError as e:
        logger.error(str(e))
        raise
    except Exception as e:
        logger.error(f"Unexpected error during certificate generation: {e}")
        raise
