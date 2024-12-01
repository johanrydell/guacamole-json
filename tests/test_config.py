import pytest

from app.config import ConfigError, load_config


def test_valid_config(monkeypatch):
    monkeypatch.setenv("TLS_PORT", "443")
    monkeypatch.setenv("CERT_VALIDITY_DAYS", "730")
    config = load_config()
    assert config["TLS_PORT"] == 443
    assert config["CERT_VALIDITY_DAYS"] == 730


def test_invalid_tls_port(monkeypatch):
    monkeypatch.setenv("TLS_PORT", "70000")  # Invalid port
    with pytest.raises(ConfigError, match="Invalid TLS_PORT"):
        load_config()


def test_invalid_cert_validity_days(monkeypatch):
    monkeypatch.setenv("CERT_VALIDITY_DAYS", "-1")  # Invalid value
    with pytest.raises(ConfigError, match="Invalid CERT_VALIDITY_DAYS"):
        load_config()


def test_default_values(monkeypatch):
    monkeypatch.delenv("TLS_PORT", raising=False)
    monkeypatch.delenv("CERT_VALIDITY_DAYS", raising=False)
    config = load_config()
    assert config["TLS_PORT"] == 8000
    assert config["CERT_VALIDITY_DAYS"] == 365
