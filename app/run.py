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
logger = logging.getLogger(__name__)

# Load configurations
config = load_config()

# Setup signal handlers
setup_signal_handlers()


def validate_file_path(
    file_path: Optional[str],
    file_type: str = "file",
    file_msg: str = "",
) -> Optional[str]:
    """
    Validates that the file or directory exists.

    Args:
        file_path (Optional[str]): Path to validate.
        file_type (str): Either "file" or "directory".
        file_msg (str): message of the file.

    Returns:
        Optional[str]: The validated file path, or None if invalid.
    """
    if not file_path:
        logger.error(f"File path is None or empty for {file_type} {file_msg}.")
        return None

    path_exists = (
        os.path.isfile(file_path) if file_type == "file" else os.path.isdir(file_path)
    )
    if not path_exists:
        logger.error(f"Invalid {file_type} {file_msg}: {file_path}")
        return None

    logger.debug(f"Validated {file_type} {file_msg}: {file_path}")
    return file_path


def generate_and_run_temp_tls():
    """
    Generates self-signed certificates and runs the application using them.
    """
    try:
        cert_pem, key_pem = generate_self_signed_cert(config)
        with tempfile.TemporaryDirectory() as temp_dir:
            cert_file_path = os.path.join(temp_dir, "cert.pem")
            key_file_path = os.path.join(temp_dir, "key.pem")

            with open(cert_file_path, "wb") as cert_file:
                cert_file.write(cert_pem)
            with open(key_file_path, "wb") as key_file:
                key_file.write(key_pem)

            logger.info("Using self-signed certificate for HTTPS.")
            start_uvicorn(cert_file_path, key_file_path)
    except Exception as e:
        logger.error(
            f"Error generating and running with self-signed certificates: {e}",
            exc_info=True,
        )
        raise


def run_with_provided_tls(key: str, cert: str, chain: Optional[str] = None):
    """
    Runs the application using provided TLS certificates.

    Args:
        key (str): Path to the private key file.
        cert (str): Path to the certificate file.
        chain (Optional[str]): Path to the certificate chain file.
    """
    try:
        if chain and os.path.exists(chain):
            with open(cert, "rb") as cert_file, open(chain, "rb") as chain_file:
                combined_cert = cert_file.read() + chain_file.read()
            combined_cert_path = tempfile.mktemp()
            with open(combined_cert_path, "wb") as combined_file:
                combined_file.write(combined_cert)
            cert = combined_cert_path

        logger.info("Using provided TLS certificate and key.")
        start_uvicorn(cert, key)
    except Exception as e:
        logger.error(
            f"Error running with provided TLS certificates: {e}", exc_info=True
        )
        raise


def start_uvicorn(cert: str, key: str):
    """
    Starts the Uvicorn server with the given certificate and key.

    Args:
        cert (str): Path to the certificate file.
        key (str): Path to the private key file.
    """
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=config["TLS_PORT"],
        log_level=config["TLS_LOG_LEVEL"],
        log_config=None,
        ssl_certfile=cert,
        ssl_keyfile=key,
    )


def main():
    """
    Main entry point for the application.
    """
    # Setup logging explicitly
    setup_logging()

    logger.info("Starting the service...")

    try:
        # Validate file paths for TLS_KEY, TLS_CERT, and optional TLS_CHAIN
        key = validate_file_path(os.getenv("TLS_KEY"), "file", "TLS_KEY")
        cert = validate_file_path(os.getenv("TLS_CERT"), "file", "TLS_CERT")
        chain = validate_file_path(os.getenv("TLS_CHAIN"), "file", "TLS_CHAIN")

        if key and cert:
            logger.info("Running with provided TLS certificates.")
            run_with_provided_tls(key, cert, chain)
        else:
            logger.warning(
                "No valid TLS_KEY or TLS_CERT provided."
                " Falling back to self-signed certificates."
            )
            generate_and_run_temp_tls()

    except Exception as e:
        logger.error(f"Service startup failed: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    main()
