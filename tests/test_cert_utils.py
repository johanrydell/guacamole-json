import pytest

from app.cert_utils import CertificateError, generate_self_signed_cert


def test_generate_self_signed_cert_valid_config():
    config = {
        "CERT_COUNTRY": "US",
        "CERT_STATE": "California",
        "CERT_LOCALITY": "San Francisco",
        "CERT_ORGANIZATION": "Example Inc",
        "CERT_COMMON_NAME": "example.com",
        "CERT_VALIDITY_DAYS": 365,
    }
    cert, key = generate_self_signed_cert(config)
    assert b"BEGIN CERTIFICATE" in cert
    assert b"BEGIN RSA PRIVATE KEY" in key


def test_generate_self_signed_cert_invalid_config():
    config = {"CERT_VALIDITY_DAYS": "-1"}  # Invalid validity days
    with pytest.raises(CertificateError):
        generate_self_signed_cert(config)
