import logging
import os
import sys

# Default Environment Configurations
ENV_DEFAULTS = {
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


def load_config():
    config = {var: os.getenv(var, default) for var, default in ENV_DEFAULTS.items()}

    try:
        config["TLS_PORT"] = int(config["TLS_PORT"])
        if not (1 <= config["TLS_PORT"] <= 65535):
            raise ValueError
    except ValueError:
        logger.error(
            f"Invalid port number: {config['TLS_PORT']}. Must be between 1 and 65535."
        )
        sys.exit(1)

    try:
        config["CERT_VALIDITY_DAYS"] = int(config["CERT_VALIDITY_DAYS"])
        if config["CERT_VALIDITY_DAYS"] <= 0:
            raise ValueError
    except ValueError:
        logger.error(
            f"Invalid certificate validity days: {config['CERT_VALIDITY_DAYS']}."
            " Must be positive."
        )
        sys.exit(1)

    return config
