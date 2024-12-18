import logging
import os
import tempfile
from typing import Optional

import uvicorn
from cert_utils import generate_self_signed_cert
from config import load_config
from custom_logging import setup_logging
from main import app
from signal_handlers import setup_signal_handlers

# Setup logging
logger = logging.getLogger(__name__)

# Load configurations
config = load_config()

# Setup signal handlers
setup_signal_handlers()


def validate_file_path(
    file_path: str,
    file_msg: str = "",
    file_access: int = os.R_OK,
) -> Optional[str]:
    """
    Validates that the file or directory exists.

    Args:
        file_path (Optional[str]): Path to validate.
        file_msg (str): message of the file.

    Returns:
        Optional[str]: The validated file path, or None if invalid.
    """
    if not file_path:
        logger.error(f"File path is None or empty: {file_msg}.")
        return None

    if not os.access(file_path, file_access):
        logger.error(f"No read access for {file_msg}: {file_path}")
        return None

    logger.debug(f"Validated {file_msg}: {file_path}")
    return file_path


def create_and_run_self_signed_tls():
    """
    Generates self-signed certificates and runs the application using them.
    We try to save the certificate in the "TLS_DIR" if possible.
    """
    try:
        # Generate a new certificate and private key
        cert_pem, key_pem = generate_self_signed_cert(config)

        # Can we save the new certificate and key?
        if os.access(config["TLS_DIR"], os.W_OK):
            logger.debug(
                f"Saving new key and certificate to TLS_DIR: {config['TLS_DIR']}"
            )

            # Create the files in the TLS_DIR
            key_file_path = os.path.join(
                config["TLS_DIR"], os.path.basename(config["TLS_TEMP_KEY"])
            )
            cert_file_path = os.path.join(
                config["TLS_DIR"], os.path.basename(config["TLS_TEMP_CERT"])
            )

            with open(key_file_path, "wb") as key_file:
                key_file.write(key_pem)
            with open(cert_file_path, "wb") as cert_file:
                cert_file.write(cert_pem)
            logger.info("Saved new self-signed certificate.")
            start_uvicorn(cert_file_path, key_file_path)

        else:
            logger.debug(f"No write access to TLS_DIR: {config['TLS_DIR']}")

            with tempfile.TemporaryDirectory() as temp_dir:
                cert_file_path = os.path.join(temp_dir, "cert.pem")
                key_file_path = os.path.join(temp_dir, "privkey.pem")

                with open(cert_file_path, "wb") as cert_file:
                    cert_file.write(cert_pem)
                with open(key_file_path, "wb") as key_file:
                    key_file.write(key_pem)

                logger.info("Using new self-signed certificate for HTTPS.")
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
    version = config["BUILD_INFO"]
    logger.info(f"[BUILD_INFO]: {version}")
    logger.info("Starting the service...")

    try:
        # Validate file read access for TLS_KEY, TLS_CERT, and optional TLS_CHAIN
        # If TLS_KEY, TLS_CERT or TLS_CHAIN have an absolute PATH, the TLS_DIR
        # is obmitted.
        key = validate_file_path(
            os.path.join(config["TLS_DIR"], config["TLS_KEY"]), "TLS_KEY"
        )
        cert = validate_file_path(
            os.path.join(config["TLS_DIR"], config["TLS_CERT"]), "TLS_CERT"
        )
        chain = validate_file_path(
            os.path.join(config["TLS_DIR"], config["TLS_CHAIN"]), "optional TLS_CHAIN"
        )

        if key and cert:
            logger.info("Running with provided TLS certificates.")
            logger.debug(f"certificate: {cert}, privkey: {key}")
            run_with_provided_tls(key, cert, chain)
            return

        #
        # Let's check for the TEMP generated certificates
        #
        key = validate_file_path(
            os.path.join(config["TLS_DIR"], config["TLS_TEMP_KEY"]), "TLS_TEMP_KEY"
        )
        cert = validate_file_path(
            os.path.join(config["TLS_DIR"], config["TLS_TEMP_CERT"]), "TLS_TEMP_CERT"
        )

        if key and cert:
            logger.info("Existing selfsigned TLS certificates found.")
            logger.debug(f"certificate: {cert}, privkey: {key}")
            run_with_provided_tls(key, cert)
            return

        logger.warning(
            "No valid TLS_KEY or TLS_CERT provided."
            " Creating self-signed certificates."
        )
        create_and_run_self_signed_tls()

    except Exception as e:
        logger.error(f"Service startup failed: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    main()
