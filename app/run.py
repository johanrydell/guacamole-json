import logging
import os
import tempfile
from typing import Optional

import uvicorn
from cert_utils import generate_self_signed_cert
from config import load_config
from logging_config import setup_logging
from main import app
from signal_handlers import setup_signal_handlers

# Setup logging
setup_logging()
logger = logging.getLogger(__name__)

# Load configurations
config = load_config()

# Setup signal handlers
setup_signal_handlers()


def validate_file_path(
    file_path: Optional[str], file_type: str = "file"
) -> Optional[str]:
    if not file_path:  # Handle None or empty string
        logger.error(f"File path is None or empty for {file_type}.")
        return None

    if file_type == "file" and not os.path.isfile(file_path):
        logger.error(f"Invalid file {file_type}: {file_path}")
        return None
    if file_type == "directory" and not os.path.isdir(file_path):
        logger.error(f"Invalid directory {file_type}: {file_path}")
        return None

    return file_path


# Run with self-signed certificates
def generate_and_run_temp_tls():
    cert_pem, key_pem = generate_self_signed_cert(config)
    with tempfile.TemporaryDirectory() as temp_dir:
        cert_file_path = os.path.join(temp_dir, "cert.pem")
        key_file_path = os.path.join(temp_dir, "key.pem")

        with open(cert_file_path, "wb") as cert_file:
            cert_file.write(cert_pem)
        with open(key_file_path, "wb") as key_file:
            key_file.write(key_pem)

        logger.info("Using self-signed certificate for HTTPS.")
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=config["TLS_PORT"],
            log_level=config["TLS_LOG_LEVEL"],
            log_config=None,
            ssl_certfile=cert_file_path,
            ssl_keyfile=key_file_path,
        )


# Run with provided TLS certificates
def run_with_provided_tls(key, cert, chain=None):
    if chain:
        if not os.path.exists(chain):
            logger.warning(
                f"Chain certificate {chain} not found. Continuing without it."
            )
        else:
            # Concatenate cert and chain
            with open(cert, "rb") as cert_file, open(chain, "rb") as chain_file:
                combined_cert = cert_file.read() + chain_file.read()
            combined_cert_path = tempfile.mktemp()
            with open(combined_cert_path, "wb") as combined_file:
                combined_file.write(combined_cert)
            cert = combined_cert_path
    logger.info("Using provided TLS certificate and key.")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=config["TLS_PORT"],
        log_level=config["TLS_LOG_LEVEL"],
        log_config=None,
        ssl_keyfile=key,
        ssl_certfile=cert,
    )


def main():
    logger.info("Starting the service")

    try:
        # Validate file paths for TLS_KEY, TLS_CERT, and optional TLS_CHAIN
        logger.info("Validating TLS_KEY, TLS_CERT, and TLS_CHAIN environment variables")
        key = validate_file_path(os.getenv("TLS_KEY"), "TLS_KEY")
        cert = validate_file_path(os.getenv("TLS_CERT"), "TLS_CERT")
        chain = validate_file_path(os.getenv("TLS_CHAIN"), "TLS_CHAIN")

        # Run with provided TLS certificates or fallback to self-signed certificates
        if key and cert:
            logger.info(f"Using provided TLS_KEY: {key}, TLS_CERT: {cert}")
            if chain:
                logger.info(f"Using optional TLS_CHAIN: {chain}")
            run_with_provided_tls(key, cert, chain)
        else:
            logger.warning(
                "No valid TLS_KEY or TLS_CERT provided. "
                "Falling back to self-signed certificates."
            )
            generate_and_run_temp_tls()

    except Exception as e:
        logger.error(f"Failed to start the service: {str(e)}", exc_info=True)
        raise


if __name__ == "__main__":
    main()
