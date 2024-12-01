import logging
import os
from typing import Any, Dict

# Default Environment Configurations
ENV_DEFAULTS: Dict[str, Any] = {
    "TLS_PORT": 8000,
    "TLS_LOG_LEVEL": "info",
    "CERT_COUNTRY": "US",
    "CERT_STATE": "California",
    "CERT_LOCALITY": "San Francisco",
    "CERT_ORGANIZATION": "Example Inc",
    "CERT_COMMON_NAME": "localhost",
    "CERT_VALIDITY_DAYS": 365,
}

logger = logging.getLogger(__name__)


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


def load_config() -> Dict[str, Any]:
    """
    Loads and validates configuration from environment variables or defaults.

    Returns:
        config (dict): A dictionary of configuration values.

    Raises:
        ConfigError: If any configuration value is invalid.
    """
    config = {var: os.getenv(var, default) for var, default in ENV_DEFAULTS.items()}

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
