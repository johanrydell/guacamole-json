import base64
import glob
import hashlib
import hmac
import json
import logging
import os
import re
import time

import requests
import uvicorn
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse


# Define a filter class
class SensitiveDataFilter(logging.Filter):
    def filter(self, record):
        # Regular expression to find and replace passwords
        record.msg = re.sub(r'("password":\s*")([^"]+)(")', r"\1****\3", record.msg)
        return True


# Configure logging
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, log_level))

# Get the root logger
logger = logging.getLogger(__name__)

# Create a filter and add it to the existing handlers (if needed)
filter = SensitiveDataFilter()

# Add the filter to all handlers that might be configured
for handler in logger.handlers:
    handler.addFilter(filter)


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
    "GUACAMOLE_URL", "http://172.16.2.127:8080"
)  # Now configurable
GUACAMOLE_TOKEN_URL = f"{GUACAMOLE_URL}/guacamole/api/tokens"
GUACAMOLE_REDIRECT_URL = f"{GUACAMOLE_URL}/guacamole/#/"


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


# Helper function to find the first JSON file in the specified directory
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
def process_json_data(json_data: dict, response: Response, request: Request):
    try:
        # Update timeout
        json_with_timeout = update_timeout(json_data, DEFAULT_TIMEOUT)
        logger.debug("Timeout updated in JSON structure.")

        # Handle WA_UID cookie
        wa_uid = request.cookies.get("WA_UID")
        if wa_uid:
            logger.debug(f"Updating username with WA_UID cookie: {wa_uid}")
            json_with_timeout["username"] = wa_uid

        # Handle additional headers
        wa_username = request.headers.get("WA_USERNAME")
        wa_password = request.headers.get("WA_PASSWORD")
        wa_domain = request.headers.get("WA_DOMAIN")

        if wa_username or wa_password or wa_domain:
            logger.debug(
                f"Received credentials: {wa_username}, {wa_password}, {wa_domain}"
            )
            # Update 'parameters' in JSON data
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


# FastAPI app
app = FastAPI()


# Route for specific JSON file (e.g., GET /1.json)
@app.get("/{filename}.json")
async def get_file_by_name(filename: str, response: Response, request: Request):
    json_file = os.path.join(JSON_CONFIG_DIR, f"{filename}.json")
    if not os.path.exists(json_file):
        logger.error(f"File {filename}.json not in directory.")
        return {"error": f"File {filename}.json not found."}

    logger.info(f"Processing JSON file: {json_file}")

    # Load the JSON data from file
    json_data = load_json_file(json_file)

    return process_json_data(json_data, response, request)


# This gives you access to all specified 'connections' in any json file
@app.get("/all")
async def get_all_configs(response: Response, request: Request):
    # Load the JSON data from all files
    json_data = all_unique_connections(JSON_CONFIG_DIR)

    return process_json_data(json_data, response, request)


# GET request handler for '/' to list all JSON files
@app.get("/", response_class=HTMLResponse)
async def list_json_files():
    json_files = glob.glob(os.path.join(JSON_CONFIG_DIR, "*.json"))
    json_files.sort()  # Sorting the files alphabetically

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
    html_content += "<h2>You can ONLY use one at the time.</h2>"

    html_content += '<p>Access to <a href="/all">all</a> configurations...'

    return HTMLResponse(content=html_content)


if __name__ == "__main__":
    key = os.getenv("TLS_KEY")
    cert = os.getenv("TLS_CERT")
    chain = os.getenv("TLS_CHAIN")

    if key and cert and chain:
        uvicorn.run(
            "app:app",
            host="0.0.0.0",
            port=4443,
            ssl_keyfile=key,  # Use the variable for key path
            ssl_certfile=cert,  # Use the variable for cert path
            ssl_ca_certs=chain,  # Use the variable for chain path
        )
    elif key and cert:
        uvicorn.run(
            "app:app",
            host="0.0.0.0",
            port=4443,
            ssl_keyfile=key,  # Use the variable for key path
            ssl_certfile=cert,  # Use the variable for cert path
        )
    else:
        uvicorn.run("app:app", host="0.0.0.0", port=8000)
