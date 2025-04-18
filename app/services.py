import base64
import glob
import hashlib
import hmac
import json
import logging
import os
import secrets
import signal
import time
from typing import Any, Dict, List, Optional, cast

import requests
from config import load_config
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from fastapi import Request
from fastapi.responses import HTMLResponse

# Loggers can now use the global filter
logger = logging.getLogger(__name__)

# Load configurations
config = load_config()

# Constants
NULL_IV = bytes.fromhex("00000000000000000000000000000000")

# This is used to verify the Guacamole connection
TEST_JSON = {
    "username": "test",
    "expires": "1446323765000",
    "connections": {
        "My Connection": {"protocol": "rdp", "parameters": {"hostname": "10.10.209.63"}}
    },
}

# Verify the variables
if len(config["JSON_SECRET_KEY"]) != 32:
    logger.error("Invalid or missing JSON_SECRET_KEY.")
    raise ValueError("Invalid JSON_SECRET_KEY.")

# Explicitly cast JSON_SECRET_KEY to str for type checking
JSON_SECRET_KEY = cast(str, config["JSON_SECRET_KEY"])

GUACAMOLE_TOKEN_URL = f"{config['GUACAMOLE_URL']}/guacamole/api/tokens"
if len(config.get("GUACAMOLE_REDIRECT_URL", "")) > 0:
    GUACAMOLE_REDIRECT_URL = config["GUACAMOLE_REDIRECT_URL"]
else:
    GUACAMOLE_REDIRECT_URL = f"{config['GUACAMOLE_URL']}/guacamole/#/"

USE_BASIC_AUTH = config["SSO"].lower() == "true"

# Basic Log information
logger.info(f"BASIC-AUTHORIZATION [SSO]: {USE_BASIC_AUTH}")
logger.info(f"[CONFIG_DIR]: {config['CONFIG_DIR']}")
logger.info(f"[DEFAULT_TIMEOUT]: {config['DEFAULT_TIMEOUT']} seconds")
logger.info(f"[GUACAMOLE_URL]: {config['GUACAMOLE_URL']}")
logger.debug(f"[GUACAMOLE_TOKEN_URL]: {GUACAMOLE_TOKEN_URL}")
logger.debug(f"[GUACAMOLE_REDIRECT_URL]: {GUACAMOLE_REDIRECT_URL}")


class ServiceError(Exception):
    """Custom exception class for service-related errors."""


def sign(secret_key: str, file_contents: bytes) -> bytes:
    key_bytes = bytes.fromhex(secret_key)
    return hmac.new(key_bytes, file_contents, hashlib.sha256).digest() + file_contents


def encrypt(secret_key: str, data: bytes) -> str:
    try:
        key_bytes = bytes.fromhex(secret_key)
        if len(key_bytes) != 16:
            raise ValueError("Secret key must be 16 bytes for AES-128 encryption.")
        cipher = AES.new(key_bytes, AES.MODE_CBC, NULL_IV)
        padded_data = pad(data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return base64.b64encode(encrypted_data).decode("utf-8")
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        raise ServiceError(f"Encryption failed: {str(e)}")


def load_json_file(file_path: str) -> Dict:
    try:
        with open(file_path, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        raise ServiceError(f"File not found: {file_path}")
    except json.JSONDecodeError as e:
        raise ServiceError(f"Invalid JSON format in file {file_path}: {e}")
    except Exception as e:
        raise ServiceError(f"Unexpected error reading file {file_path}: {e}")


def authenticate_with_guacamole(encrypted_data: str) -> str:
    try:
        response = requests.post(
            GUACAMOLE_TOKEN_URL, data={"data": encrypted_data}, verify=False
        )
        response.raise_for_status()
        token = response.json().get("authToken")
        if not token:
            raise ServiceError("Token not found in Guacamole response.")
        return token
    except requests.RequestException as e:
        raise ServiceError(f"Guacamole authentication failed: {e}")


def find_json_files(directory: str) -> List[str]:
    json_files = glob.glob(os.path.join(directory, "*.json"))
    if not json_files:
        logging.error(f"No JSON files found in directory: {directory}")
        return []
    return sorted(json_files)


def all_unique_connections(directory: str) -> Dict:
    json_files = find_json_files(directory)
    merged_connections = {}

    for file in json_files:
        json_data = load_json_file(file)
        connections = json_data.get("connections", {})
        for conn_name, conn_data in connections.items():
            if conn_name not in merged_connections:
                merged_connections[conn_name] = conn_data

    # Generate a random username and current epoch expiration
    random_username = secrets.token_hex(8)  # Generates 16-character hex string
    current_time = int(time.time() * 1000)  # Current time in milliseconds

    # Final response with username, expires, and connections
    response = {
        "username": random_username,
        "expires": str(current_time),
        "connections": merged_connections,
    }

    return response


def update_timeout(json_data: Dict, timeout: int) -> Dict:
    current_epoch = int(time.time() * 1000)
    json_data["expires"] = current_epoch + (timeout * 1000)
    return json_data


def process_json_guac(json_data: Dict) -> HTMLResponse:
    try:
        json_with_timeout = prepare_json_with_timeout(json_data)
        token = generate_token(json_with_timeout)
        redirect_url = get_redirect_url(json_with_timeout, token)
        return build_redirect_response(redirect_url)

    except ServiceError as e:
        logger.error(f"Service error: {e}")
        return {"error": str(e)}
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return {"error": str(e)}


def prepare_json_with_timeout(json_data: Dict) -> Dict:
    json_new = update_timeout(json_data, config["DEFAULT_TIMEOUT"])
    logger.debug(
        f"Connections with Metadata before sign: \n{json.dumps(json_new, indent=4)}"
    )
    return json_new


def generate_token(json_data: Dict) -> str:
    signed = sign(config["JSON_SECRET_KEY"], json.dumps(json_data).encode("utf-8"))
    encrypted = encrypt(config["JSON_SECRET_KEY"], signed)
    return authenticate_with_guacamole(encrypted)


def get_redirect_url(json_data: Dict, token: str) -> str:
    username = json_data.get("username", "Unknown")
    connections = json_data.get("connections", {})
    conn_names = list(connections.keys())

    logger.info(f"Username: {username}, got connection(s) for: {', '.join(conn_names)}")

    first_conn: Dict[str, Any] = next(iter(connections.values()), {})
    if isinstance(first_conn, dict):
        parameters = first_conn.get("parameters", {})
        if isinstance(parameters, dict):
            redirect_url = parameters.get("redirect-url")
            if redirect_url:
                logger.info(f"Custom redirect server: {redirect_url}")
                return f"{redirect_url}/guacamole/#/?token={token}"

    return f"{GUACAMOLE_REDIRECT_URL}?token={token}"


def build_redirect_response(redirect_url: str) -> HTMLResponse:
    html_content = (
        "<html>\n"
        "<head>\n"
        "<script>\n"
        "localStorage.clear();\n"
        f'window.location.href = "{redirect_url}"\n'
        "</script>\n"
        "</head>\n"
        "<body>\n"
        "<p>Redirecting to Guacamole...</p>\n"
        "</body>\n"
        "</html>"
    )
    return HTMLResponse(content=html_content)


def get_auth_credentials(
    request: Request, username: Optional[str], password: Optional[str]
):
    if USE_BASIC_AUTH:
        return username, password, ""
    return (
        request.headers.get("WA_USERNAME", ""),
        request.headers.get("WA_PASSWORD", ""),
        request.headers.get("WA_DOMAIN", ""),
    )


def inject_credentials_if_sso(
    json_data: Dict, wa_username: str, wa_password: str, wa_domain: str
):
    for conn_data in json_data.get("connections", {}).values():
        if conn_data.get("parameters", {}).get("sso") == "true":
            params = conn_data.setdefault("parameters", {})
            if len(wa_username) > 0:
                params["username"] = wa_username
            if len(wa_password) > 0:
                params["password"] = wa_password
            if len(wa_domain) > 0:
                params["domain"] = wa_domain


def set_effective_username(
    json_data: Dict, request: Request, wa_username: Optional[str]
):
    wa_uid = request.cookies.get("WA_UID")
    if wa_uid:
        json_data["username"] = wa_uid
    elif wa_username:
        json_data["username"] = wa_username
    else:
        random_username = secrets.token_hex(8)
        json_data["username"] = f"ID_{random_username}"


def process_json_data(
    json_data: Dict, request: Request, username: Optional[str], password: Optional[str]
) -> HTMLResponse:
    try:
        my_json = update_timeout(json_data, config["DEFAULT_TIMEOUT"])

        wa_username, wa_password, wa_domain = get_auth_credentials(
            request, username, password
        )
        inject_credentials_if_sso(my_json, wa_username, wa_password, wa_domain)
        set_effective_username(my_json, request, wa_username)

        logger.debug(
            f"Connections with Metadata before sign: \n{json.dumps(my_json, indent=4)}"
        )

        token = get_guacamole_token(my_json)
        redirect_url = get_redirect_url(my_json, token)
        return build_redirect_response(redirect_url)

    except ServiceError as e:
        logger.error(f"Service error: {e}")
        return {"error": str(e)}
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return {"error": str(e)}


def check_guacamole_connection():
    try:
        token = get_guacamole_token(TEST_JSON)
        if token:
            return True
    except Exception:
        logger.fatal("Connection to guacamole service failed!")
        logger.fatal(f"Check URL: {GUACAMOLE_TOKEN_URL}")
        logger.fatal("Check JSON_SECRET_KEY")
        # Ensure logs are flushed before exit
        for handler in logger.handlers:
            handler.flush()
        os.kill(os.getpid(), signal.SIGINT)


def get_guacamole_token(data: Dict):
    data_with_time = update_timeout(data, config["DEFAULT_TIMEOUT"])
    signed_data = sign(
        config["JSON_SECRET_KEY"], json.dumps(data_with_time).encode("utf-8")
    )
    encrypted_data = encrypt(config["JSON_SECRET_KEY"], signed_data)
    return authenticate_with_guacamole(encrypted_data)
