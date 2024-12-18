import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


class CertificateError(Exception):
    """Custom exception for certificate generation errors."""


def create_key_pair(config: Dict[str, str]):
    """
    Generates a private key based on the specified key type and parameters.

    Args:
        config (Dict[str, str]): Configuration for the key type and parameters.

    Returns:
        Asymmetric private key object: The generated private key.
    """
    key_type = config.get("KEY_TYPE", "RSA").upper()

    if key_type == "RSA":
        key_size = int(config.get("KEY_SIZE", 2048))
        if key_size not in [2048, 4096]:
            raise CertificateError("RSA key size must be 2048 or 4096.")
        logger.debug(f"Generating RSA private key with size {key_size}...")
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    elif key_type == "EC":
        curve_name = config.get("CURVE", "SECP256R1").upper()
        if curve_name == "SECP256R1":
            logger.debug("Generating elliptic curve key using SECP256R1...")
            return ec.generate_private_key(ec.SECP256R1())
        elif curve_name == "SECP384R1":
            logger.debug("Generating elliptic curve key using SECP384R1...")
            return ec.generate_private_key(ec.SECP384R1())
        elif curve_name == "SECP521R1":
            logger.debug("Generating elliptic curve key using SECP521R1...")
            return ec.generate_private_key(ec.SECP521R1())
        else:
            raise CertificateError(f"Unsupported EC curve: {curve_name}")

    elif key_type == "ED25519":
        logger.debug("Generating Ed25519 private key...")
        return Ed25519PrivateKey.generate()

    elif key_type == "ED448":
        logger.debug("Generating Ed448 private key...")
        return Ed448PrivateKey.generate()

    else:
        raise CertificateError(f"Unsupported key type: {key_type}")


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
    key, subject: x509.Name, config: Dict[str, str]
) -> x509.Certificate:
    """
    Generates a self-signed X.509 certificate.

    Args:
        key: The private key for signing the certificate (RSA, EC, Ed25519, or Ed448).
        subject (x509.Name): The subject/issuer of the certificate.
        config (Dict[str, str]): Configuration for certificate validity and attributes.

    Returns:
        x509.Certificate: The generated self-signed certificate.
    """
    logger.debug("Generating self-signed certificate...")
    validity_days = int(config.get("CERT_VALIDITY_DAYS", 365))
    try:
        builder = (
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
        )

        # Determine the signing algorithm
        if isinstance(key, (Ed25519PrivateKey, Ed448PrivateKey)):
            return builder.sign(key, None)  # No algorithm for Ed25519/Ed448
        else:
            return builder.sign(key, hashes.SHA256())
    except Exception as e:
        raise CertificateError(f"Failed to generate self-signed certificate: {e}")


def generate_self_signed_cert(config: Dict[str, str]) -> Tuple[bytes, bytes]:
    try:
        logger.info("Starting self-signed certificate generation...")
        key = create_key_pair(config)
        subject = create_certificate_subject(config)
        cert = create_self_signed_cert(key, subject, config)

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        # Use PKCS8 format for Ed25519 and Ed448 keys
        if isinstance(key, (Ed25519PrivateKey, Ed448PrivateKey)):
            key_pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        else:
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
