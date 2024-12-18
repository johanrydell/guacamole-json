import unittest

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from app.cert_utils import CertificateError, generate_self_signed_cert


class TestCertificateGeneration(unittest.TestCase):
    def setUp(self):
        # Base configuration for the tests
        self.base_config = {
            "CERT_COUNTRY": "US",
            "CERT_STATE": "California",
            "CERT_LOCALITY": "San Francisco",
            "CERT_ORGANIZATION": "Test Org",
            "CERT_COMMON_NAME": "localhost",
            "CERT_VALIDITY_DAYS": "365",
        }

    def test_rsa_key_generation_2048(self):
        config = {**self.base_config, "KEY_TYPE": "RSA", "KEY_SIZE": "2048"}
        cert_pem, key_pem = generate_self_signed_cert(config)
        self.assertIn(b"BEGIN CERTIFICATE", cert_pem)
        self.assertIn(b"BEGIN RSA PRIVATE KEY", key_pem)

    def test_rsa_key_generation_4096(self):
        config = {**self.base_config, "KEY_TYPE": "RSA", "KEY_SIZE": "4096"}
        cert_pem, key_pem = generate_self_signed_cert(config)
        self.assertIn(b"BEGIN CERTIFICATE", cert_pem)
        self.assertIn(b"BEGIN RSA PRIVATE KEY", key_pem)

    def test_invalid_rsa_key_size(self):
        config = {**self.base_config, "KEY_TYPE": "RSA", "KEY_SIZE": "1024"}
        with self.assertRaises(CertificateError):
            generate_self_signed_cert(config)

    def test_ec_key_generation_secp256r1(self):
        config = {**self.base_config, "KEY_TYPE": "EC", "CURVE": "SECP256R1"}
        cert_pem, key_pem = generate_self_signed_cert(config)
        self.assertIn(b"BEGIN CERTIFICATE", cert_pem)
        cert = x509.load_pem_x509_certificate(cert_pem)
        self.assertIsInstance(cert.public_key(), ec.EllipticCurvePublicKey)

    def test_invalid_ec_curve(self):
        config = {**self.base_config, "KEY_TYPE": "EC", "CURVE": "INVALID_CURVE"}
        with self.assertRaises(CertificateError):
            generate_self_signed_cert(config)

    def test_ed25519_key_generation(self):
        config = {**self.base_config, "KEY_TYPE": "ED25519"}
        cert_pem, key_pem = generate_self_signed_cert(config)
        self.assertIn(b"BEGIN CERTIFICATE", cert_pem)

    def test_certificate_subject(self):
        config = self.base_config.copy()
        cert_pem, key_pem = generate_self_signed_cert(config)
        cert = x509.load_pem_x509_certificate(cert_pem)
        subject = cert.subject
        self.assertEqual(
            subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value, "US"
        )
        self.assertEqual(
            subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
            "localhost",
        )

    def test_invalid_key_type(self):
        config = {**self.base_config, "KEY_TYPE": "INVALID_TYPE"}
        with self.assertRaises(CertificateError):
            generate_self_signed_cert(config)

    def test_certificate_validity_period(self):
        config = {**self.base_config, "CERT_VALIDITY_DAYS": "30"}
        cert_pem, key_pem = generate_self_signed_cert(config)
        cert = x509.load_pem_x509_certificate(cert_pem)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        self.assertEqual((not_after - not_before).days, 30)


if __name__ == "__main__":
    unittest.main()
