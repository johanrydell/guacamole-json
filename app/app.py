import base64
import glob
import hashlib
import hmac
import json
import logging
import os
import re
import tempfile
import time
from datetime import datetime, timedelta, timezone

import requests
import uvicorn
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509.oid import NameOID
from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials


#
# We have to remove the password from any logs
# The best way is to do a filter for the log class
#
class SensitiveDataFilter(logging.Filter):
    def filter(self, record):
        # Ensure the message is a string before applying the regex
        if isinstance(record.msg, dict):
            record.msg = json.dumps(record.msg)  # Convert dict to string for filtering
        elif not isinstance(record.msg, str):
            record.msg = str(record.msg)  # Convert other types to string

        # Regular expression to find and replace passwords in double-quoted
        # and single-quoted formats
        record.msg = re.sub(
            r'("password":\s*")([^"]+)(")', r"\1****\3", record.msg
        )  # Handles double quotes
        record.msg = re.sub(
            r"(\'password\':\s*\')([^\']+)(\')", r"\1****\3", record.msg
        )  # Handles single quotes
        return True


# Configure logging - Default is "INFO"
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, log_level))

# Apply the SensitiveDataFilter globally
sensitive_filter = SensitiveDataFilter()

# Add the filter to the root logger
root_logger = logging.getLogger()
for handler in root_logger.handlers:
    handler.addFilter(sensitive_filter)

# Loggers can now use the global filter
logger = logging.getLogger("app")


# Constants (now configurable through environment variables)
NULL_IV = bytes.fromhex("00000000000000000000000000000000")
DEFAULT_TIMEOUT = int(os.getenv("DEFAULT_TIMEOUT", 3600 * 8))  # Default to 8 hours
JSON_SECRET_KEY = os.getenv(
    "JSON_SECRET_KEY", "4C0B569E4C96DF157EEE1B65DD0E4D41"
)  # The static key is the guacamole test key

if not JSON_SECRET_KEY or len(JSON_SECRET_KEY) != 32:
    logger.error("Invalid or missing JSON_SECRET_KEY")
    raise ValueError("Invalid or missing JSON_SECRET_KEY.")
JSON_CONFIG_DIR = os.getenv("JSON_CONFIG_DIR", "app")
GUACAMOLE_URL = os.getenv(
    "GUACAMOLE_URL", "http://127.0.0.1:8080"
)  # Where should the use be redirected too?
# Static postfix values of the guacamole server
GUACAMOLE_TOKEN_URL = f"{GUACAMOLE_URL}/guacamole/api/tokens"
GUACAMOLE_REDIRECT_URL = f"{GUACAMOLE_URL}/guacamole/#/"

# Uvicorn port
PORT = os.getenv("PORT", 8000)

# Read the BASIC parameter from the environment
# This will require basic authorization for any URL except '/'
USE_BASIC_AUTH = os.getenv("BASIC", "false").lower() == "true"

# Initialize Basic Authentication
security = HTTPBasic()


# No more unsecure HTTP
def generate_self_signed_cert():
    # Generate RSA key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate self-signed certificate
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Inc"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # Serialize certificate and key to PEM format
    cert_pem = cert.public_bytes(Encoding.PEM)
    key_pem = key.private_bytes(
        Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
    )

    return cert_pem, key_pem


# This is the server when no TLS certificates was presented
# selfsigned certificates are created
def generate_and_run_temp_tls():
    # Generate self-signed certificate and key
    cert_pem, key_pem = generate_self_signed_cert()

    # Write cert and key to temporary files
    with tempfile.NamedTemporaryFile(
        delete=False
    ) as cert_file, tempfile.NamedTemporaryFile(delete=False) as key_file:
        cert_file.write(cert_pem)
        key_file.write(key_pem)
        cert_file_path = cert_file.name
        key_file_path = key_file.name

    try:
        # Start Uvicorn with the temporary certificate and key
        uvicorn.run(
            "app:app",
            host="0.0.0.0",
            port=PORT,
            ssl_certfile=cert_file_path,
            ssl_keyfile=key_file_path,
        )
    finally:
        # Clean up temporary files
        os.unlink(cert_file_path)
        os.unlink(key_file_path)


# The normal way to run Uvicorn with provided certificates
def run_with_provided_tls(key, cert, chain=None):
    # Start Uvicorn with provided certificate and key
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=PORT,
        ssl_keyfile=key,
        ssl_certfile=cert,
        ssl_ca_certs=chain,
    )


# Function to sign the file using HMAC/SHA-256
def sign(JSON_SECRET_KEY, file_contents):
    key_bytes = bytes.fromhex(JSON_SECRET_KEY)
    hmac_signature = hmac.new(key_bytes, file_contents, hashlib.sha256).digest()
    return hmac_signature + file_contents


# Function to encrypt data using AES-128-CBC with a null IV
def encrypt(JSON_SECRET_KEY, data):
    try:
        key_bytes = bytes.fromhex(JSON_SECRET_KEY)
        if len(key_bytes) != 16:
            raise ValueError(
                "Secret key must be exactly 16 bytes"
                "(32 hex characters) for AES-128 encryption."
            )

        cipher = AES.new(key_bytes, AES.MODE_CBC, NULL_IV)
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        base64_encoded = base64.b64encode(encrypted_data).decode("utf-8")

        return base64_encoded
    except ValueError as e:
        logger.error(f"Encryption error: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during encryption: {e}")
        raise


# Helper function to read a json file and return json data
def load_json_file(JSON_FILENAME):
    try:
        with open(JSON_FILENAME, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.error(f"File not found: {JSON_FILENAME}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"JSON decoding error in file {JSON_FILENAME}: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error while loading {JSON_FILENAME}: {e}")
        raise


# Helper function to send POST request to Guacamole
# We want the authToken
def authenticate_with_guacamole(encrypted_data):
    try:
        post_data = {"data": encrypted_data}
        # ToDo: verify internal TLS servers
        guacamole_response = requests.post(
            GUACAMOLE_TOKEN_URL, data=post_data, verify=False
        )

        if guacamole_response.status_code != 200:
            logger.error(
                "Guacamole authentication failed, "
                f"status code: {guacamole_response.status_code}"
            )
            raise Exception(
                "Failed to authenticate with Guacamole, "
                f"status code: {guacamole_response.status_code}"
            )

        guac_data = guacamole_response.json()
        token = guac_data.get("authToken")

        if not token:
            logger.error("Token not found in Guacamole response")
            raise Exception("Token not found in Guacamole response")

        return token

    except requests.RequestException as e:
        logger.error(f"Request failed to Guacamole: {e}")
        raise


# Helper function to find the JSON files in the specified directory
def find_json_files(directory):
    json_files = glob.glob(os.path.join(directory, "*.json"))

    if not json_files:
        raise Exception(f"No JSON files found in directory: {directory}")

    # Sort the files
    json_files.sort()

    # Return the files found
    return json_files


# Function to process JSON files and merge unique 'connections' into one json structure
def all_unique_connections(directory):
    # Find and load the first JSON file
    json_files = find_json_files(directory)

    with open(json_files[0], "r") as first_file:
        first_json_data = json.load(first_file)  # Read the first JSON file into memory

    # Initialize a dictionary to store unique connections
    merged_connections = first_json_data.get("connections", {})

    # Loop through the remaining JSON files
    for json_file in json_files[1:]:
        json_data = load_json_file(json_file)

        # Check if 'connections' exists in the JSON data
        if "connections" in json_data:
            for conn_name, conn_data in json_data["connections"].items():
                if conn_name not in merged_connections:
                    # Add unique connection to the merged dictionary
                    merged_connections[conn_name] = conn_data
                else:
                    print(f"Connection '{conn_name}' already exists, skipping...")

    # Update the first JSON data with merged connections
    first_json_data["connections"] = merged_connections

    return first_json_data


# Helper function to update the "expires" field in the JSON object
def update_timeout(json_data, default_timeout):
    try:
        current_epoch = int(time.time() * 1000)  # Get current time in milliseconds
        new_expiration = current_epoch + (
            default_timeout * 1000
        )  # Add default_timeout to current time in milliseconds

        # Set or update the "expires" key in the json_data dictionary
        json_data["expires"] = new_expiration

        return json_data  # Return the updated dictionary for encryption
    except Exception as e:
        raise Exception(f"Error processing JSON data: {str(e)}")


# Refactored function to handle the common flow for loading,
# signing, encrypting, and authentication
def process_json_data(json_data: dict, request: Request, credentials: tuple):
    try:
        # Update timeout
        json_with_timeout = update_timeout(json_data, DEFAULT_TIMEOUT)
        logger.debug("Timeout updated in JSON structure.")

        # Handle WA_UID cookie
        wa_uid = request.cookies.get("WA_UID")
        if wa_uid:
            logger.debug(f"Updating username with WA_UID cookie: {wa_uid}")
            json_with_timeout["username"] = wa_uid

        # Handle additional headers and basic_authorization
        if USE_BASIC_AUTH:
            wa_username, wa_password = credentials
            wa_domain = None
        else:
            wa_username = request.headers.get("WA_USERNAME")
            wa_password = request.headers.get("WA_PASSWORD")
            wa_domain = request.headers.get("WA_DOMAIN")

        if wa_username or wa_password or wa_domain:
            logger.debug(f"Received credentials: {wa_username}, ****, {wa_domain}")
            # Update 'parameters' in JSON data, but ONLY is "sso": "true" is present
            for connection, details in json_with_timeout.get("connections", {}).items():
                if (
                    "parameters" in details
                    and details["parameters"].get("sso") == "true"
                ):
                    if wa_username:
                        details["parameters"]["username"] = wa_username
                    if wa_password:
                        details["parameters"]["password"] = wa_password
                    if wa_domain:
                        details["parameters"]["domain"] = wa_domain

        # Further processing
        logger.debug(f"Final JSON Configuration: {json_with_timeout}")
        signed_data = sign(
            JSON_SECRET_KEY, json.dumps(json_with_timeout).encode("utf-8")
        )
        encrypted_data = encrypt(JSON_SECRET_KEY, signed_data)
        token = authenticate_with_guacamole(encrypted_data)

        # Redirecting
        logger.info("Redirecting to Guacamole with token.")
        return RedirectResponse(
            url=f"{GUACAMOLE_REDIRECT_URL}?token={token}", status_code=303
        )

    except Exception as e:
        logger.error(f"Error processing JSON file: {e}")
        return {"error": str(e)}


def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    # Extract username and password
    username = credentials.username
    password = credentials.password

    # Log both username and password
    logging.info(f"Username: {username}, Password: {password}")

    return username, password


# FastAPI app
app = FastAPI()


# Route for specific JSON file
@app.get("/{filename}.json")
async def get_file_by_name(
    filename: str,
    request: Request,
    credentials: tuple = Depends(authenticate_user) if USE_BASIC_AUTH else None,
):
    json_file = os.path.join(JSON_CONFIG_DIR, f"{filename}.json")
    if not os.path.exists(json_file):
        logger.error(f"File {filename}.json not in directory.")
        return {"error": f"File {filename}.json not found."}

    logger.info(f"Processing JSON file: {json_file}")

    # Load the JSON data from file
    json_data = load_json_file(json_file)

    return process_json_data(json_data, request, credentials)


# This gives you access to all specified 'connections' in any json file
@app.get("/combined")
async def get_all_configs(
    request: Request,
    credentials: tuple = Depends(authenticate_user) if USE_BASIC_AUTH else None,
):
    # Load the JSON data from all files
    json_data = all_unique_connections(JSON_CONFIG_DIR)

    return process_json_data(json_data, request, credentials)


@app.get("/basic")
def test_basic_auth(
    credentials: tuple = Depends(authenticate_user) if USE_BASIC_AUTH else None,
):
    if USE_BASIC_AUTH:
        username, password = credentials
        return {
            "message": f"Welcome, {username}!",
            "username": username,
            # "password": password,
        }
    else:
        return {"message": "Basic Authentication is not enabled"}


# GET request handler for '/' to list all JSON files
@app.get("/", response_class=HTMLResponse)
async def list_json_files():
    json_files = glob.glob(os.path.join(JSON_CONFIG_DIR, "*.json"))
    json_files.sort()  # Sorting the files alphabetically

    # Check if there are JSON files available
    if not json_files:
        html_content = """
            <h1>No Configuration Files Found</h1>
            <p>No JSON configuration files were found in the directory.</p>
            <p>Please refer to the
            <a href="https://guacamole.apache.org/doc/gug/json-auth.html"
            target="_blank"> Guacamole JSON Authentication documentation </a>
            for details on setting up JSON configuration files.</p>
        """
    else:
        # Create an HTML page listing all .json files with clickable links
        html_content = "<h1>Configuration Files</h1><ul>"
        for json_file in json_files:
            file_name = os.path.basename(json_file)
            file_name_without_extension = os.path.splitext(file_name)[0]
            # Create a link to view each JSON file
            html_content += (
                f'<li><a href="/{file_name}">{file_name_without_extension}</a></li>'
            )
        html_content += "</ul>"
        html_content += "<h2>You can ONLY use one at a time.</h2>"
        html_content += '<p>Access to <a href="/combined">all</a> configurations...'

    return HTMLResponse(content=html_content)


if __name__ == "__main__":
    key = os.getenv("TLS_KEY")
    cert = os.getenv("TLS_CERT")
    chain = os.getenv("TLS_CHAIN")

    if key and cert:
        # Run with provided TLS settings
        run_with_provided_tls(key, cert, chain)
    else:
        # Fallback to self-signed certificate
        generate_and_run_temp_tls()
