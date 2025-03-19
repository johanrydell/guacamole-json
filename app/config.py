import logging
import os
from typing import Any, Dict

# Default Environment Configurations
ENV_DEFAULTS: Dict[str, Any] = {
    "BUILD_INFO": "N/A",
    "TLS_PORT": 8000,
    "TLS_LOG_LEVEL": "info",
    "TLS_DIR": "/tls",
    "TLS_CERT": "cert.pem",
    "TLS_KEY": "privkey.pem",
    "TLS_CHAIN": "chain.pem",
    "TLS_TEMP_CERT": "self-signed_cert.pem",
    "TLS_TEMP_KEY": "self-signed_privkey.pem",
    "CERT_COUNTRY": "US",
    "CERT_STATE": "California",
    "CERT_LOCALITY": "San Francisco",
    "CERT_ORGANIZATION": "Example Inc",
    "CERT_COMMON_NAME": "localhost",
    "CERT_VALIDITY_DAYS": 365,
    "KEY_TYPE": "RSA",
    "KEY_SIZE": 4096,  # Changed to integer
}

PROJECT_DEFAULTS: Dict[str, Any] = {
    "JSON_SECRET_KEY": "",
    "CONFIG_DIR": ".",
    "GUACAMOLE_URL": "http://127.0.0.1:8080",
    "GUACAMOLE_REDIRECT_URL": "",
    "SSO": "true",
    "GUAC_LEGACY": "true",
    "DEFAULT_TIMEOUT": 3600 * 24,
}

logger = logging.getLogger(__name__)
config = None  # Global config variable


class ConfigError(Exception):
    """Custom exception for configuration errors."""


def validate_int(value: Any, min_val: int, max_val: int, name: str) -> int:
    """
    Validates and converts a value to an integer within a specified range.
    """
    try:
        value = int(value)
        if not (min_val <= value <= max_val):
            raise ValueError
        return value
    except ValueError:
        raise ConfigError(
            f"Invalid {name}: {value}. "
            f"Must be an integer between {min_val} and {max_val}."
        )


def load_config(force_reload=False) -> Dict[str, Any]:
    """
    Loads and validates configuration from environment variables or defaults.

    Args:
        force_reload (bool): If True, forces reloading of the configuration.

    Returns:
        config (dict): A dictionary of configuration values.

    Raises:
        ConfigError: If any configuration value is invalid.
    """
    global config
    if config is not None and not force_reload:
        return config

    config = {var: os.getenv(var, default) for var, default in ENV_DEFAULTS.items()}
    config.update(
        {var: os.getenv(var, default) for var, default in PROJECT_DEFAULTS.items()}
    )

    try:
        # Validate TLS_PORT
        config["TLS_PORT"] = validate_int(config["TLS_PORT"], 1, 65535, "TLS_PORT")

        # Validate CERT_VALIDITY_DAYS
        config["CERT_VALIDITY_DAYS"] = validate_int(
            config["CERT_VALIDITY_DAYS"], 1, 10 * 365, "CERT_VALIDITY_DAYS"
        )

    except ConfigError as e:
        logger.error(str(e))
        raise

    logger.info("Configuration loaded successfully.")
    return config
