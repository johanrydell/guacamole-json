import base64
import glob
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from typing import Dict, List, Optional, cast

import requests
from config import load_config
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from fastapi import Request
from fastapi.responses import RedirectResponse

# Loggers can now use the global filter
logger = logging.getLogger(__name__)

# Load configurations
config = load_config()

# Constants
NULL_IV = bytes.fromhex("00000000000000000000000000000000")

# Verify the variables
if len(config["JSON_SECRET_KEY"]) != 32:
    logger.error("Invalid or missing JSON_SECRET_KEY.")
    raise ValueError("Invalid JSON_SECRET_KEY.")

# Explicitly cast JSON_SECRET_KEY to str for type checking
JSON_SECRET_KEY = cast(str, config["JSON_SECRET_KEY"])

GUACAMOLE_TOKEN_URL = f"{config['GUACAMOLE_URL']}/guacamole/api/tokens"
GUACAMOLE_REDIRECT_URL = f"{config['GUACAMOLE_URL']}/guacamole/#/"
USE_BASIC_AUTH = config["SSO"].lower() == "true"

# Basic Log information
logger.info(f"BASIC-AUTHORIZATION [SSO]: {USE_BASIC_AUTH}")
logger.info(f"[CONFIG_DIR]: {config['CONFIG_DIR']}")
logger.info(f"[DEFAULT_TIMEOUT]: {config['DEFAULT_TIMEOUT']} seconds")
logger.info(f"[GUACAMOLE_URL]: {config['GUACAMOLE_URL']}")


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
        raise ServiceError(f"No JSON files found in directory: {directory}")
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


def process_json_data(
    json_data: Dict, request: Request, username: Optional[str], password: Optional[str]
) -> RedirectResponse:
    try:
        # Update the timeout
        json_with_timeout = update_timeout(json_data, config["DEFAULT_TIMEOUT"])

        # Do we have SSO data, otherwise try to get from HEADERS
        if USE_BASIC_AUTH:
            wa_username, wa_password, wa_domain = username, password, None
        else:
            wa_username = request.headers.get("WA_USERNAME")
            wa_password = request.headers.get("WA_PASSWORD")
            wa_domain = request.headers.get("WA_DOMAIN")

        # Replace username, password and domain ONLY if "sso" is True
        # and we have a new value.
        for conn_name, conn_data in json_with_timeout.get("connections", {}).items():
            if conn_data.get("parameters", {}).get("sso") == "true":
                if wa_username:
                    conn_data["parameters"]["username"] = wa_username
                if wa_password:
                    conn_data["parameters"]["password"] = wa_password
                if wa_domain:
                    conn_data["parameters"]["domain"] = wa_domain

        # If we have a WA_UID, it should be used
        # otherwise the wa_username
        # finally generate a new value
        wa_uid = request.cookies.get("WA_UID")
        if wa_uid:
            json_with_timeout["username"] = wa_uid
        elif wa_username:
            json_with_timeout["username"] = wa_username
        else:
            # Generate a random username and current epoch expiration
            random_username = secrets.token_hex(8)  # Generates 16-character hex string
            json_with_timeout["username"] = f"ID_{random_username}"

        cons = json.dumps(json_with_timeout, indent=4)
        logger.debug(f"Connections with Metadata befor sign: \n{cons}")

        signed_data = sign(
            config["JSON_SECRET_KEY"], json.dumps(json_with_timeout).encode("utf-8")
        )
        encrypted_data = encrypt(config["JSON_SECRET_KEY"], signed_data)
        token = authenticate_with_guacamole(encrypted_data)

        # Extract username
        username = json_with_timeout.get("username", "Unknown")

        # Extract connection names
        conn_names = list(json_with_timeout.get("connections", {}).keys())

        # Log the information
        logger.info(
            f"Username: {username}, got connection(s) for: {', '.join(conn_names)}"
        )
        return RedirectResponse(
            url=f"{GUACAMOLE_REDIRECT_URL}?token={token}", status_code=303
        )
    except ServiceError as e:
        logger.error(f"Service error: {e}")
        return {"error": str(e)}
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return {"error": str(e)}
