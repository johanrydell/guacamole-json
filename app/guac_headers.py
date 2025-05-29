import json
import logging
import os
import re
import time
from typing import Any, Dict, Optional
from urllib.parse import unquote

from config import load_config
from custom_logging import setup_logging

# Set up logging
logger = logging.getLogger(__name__)

DEFAULT_PARAMETERS = {"recording-path": "/tmp/${GUAC_USERNAME}"}

DEFAULT_RDP_PARAMETERS = {
    "port": "3389",
    "security": "any",
    "ignore-cert": "true",
    "enable-drive": "true",
    "drive-path": "/tmp/${GUAC_USERNAME}",
    "create-drive-path": "true",
    "enable-printing": "true",
}

DEFAULT_SSH_PARAMETERS = {
    "typescript-path": "/tmp/${GUAC_USERNAME}",
}

# Load configurations
config = load_config()


class URLParser:
    ALLOWED_PROTOCOLS = {"vnc", "rdp", "ssh", "telnet", "kubernetes"}

    @staticmethod
    def _custom_query_parser(query: str) -> dict:
        pattern = re.compile(r"(?:(?:^|&)([^=]+)=)")
        matches = list(pattern.finditer(query))
        parsed = {}
        for i, match in enumerate(matches):
            key = match.group(1)
            value_start = match.end()
            value_end = matches[i + 1].start() if i + 1 < len(matches) else len(query)
            value = query[value_start:value_end]
            parsed[key] = value
        return parsed

    def parse(self, raw_url: str) -> dict:
        url = unquote(raw_url)
        protocol_split = url.split("://", 1)
        if len(protocol_split) != 2:
            raise ValueError("Missing or invalid protocol")

        protocol, rest = protocol_split
        if protocol not in self.ALLOWED_PROTOCOLS:
            raise ValueError(f"Unsupported protocol: {protocol}")

        parsed: Dict[str, Any] = {"protocol": protocol}

        # Safely isolate query section using the clearer '/?' split
        query = ""
        if "/?" in rest:
            rest, query = rest.split("/?", 1)

        port = None
        host_port_path = rest.split("/", 1)[0]
        if ":" in host_port_path.split("@")[-1]:
            host_parts = host_port_path.rsplit(":", 1)
            if len(host_parts) == 2:
                rest = rest.replace(f":{host_parts[1]}", "", 1)
                port = host_parts[1]
                if port:
                    parsed["port"] = port

        if "@" in rest:
            creds, hostname = rest.rsplit("@", 1)
            if ":" in creds:
                username, password = creds.split(":", 1)
                parsed["username"] = username
                parsed["password"] = password
            else:
                parsed["username"] = creds
            parsed["hostname"] = hostname.rstrip("/")
        else:
            parsed["hostname"] = rest.split("/", 1)[0].rstrip("/")

        if query:
            parsed["arguments"] = self._custom_query_parser(query)

        return parsed


def fallback_username():
    now = int(time.time() * 1000)
    return f"da_{now:x}"


def resolve_path(pre_path: str, sub_path: str) -> str:
    sub_path = sub_path.lstrip("/\\")  # Handle both Unix and Windows
    path = os.path.join(pre_path, sub_path)
    return path


def resolve_vars_in_structure(data, variables: dict):
    if isinstance(data, dict):
        return {k: resolve_vars_in_structure(v, variables) for k, v in data.items()}
    elif isinstance(data, list):
        return [resolve_vars_in_structure(item, variables) for item in data]
    elif isinstance(data, str):
        return resolve_vars(data, variables)
    else:
        return data  # leave other types (int, bool, etc.) unchanged


def resolve_vars(string: str, variables: dict) -> str:
    def replacer(match):
        key = match.group(1)
        return variables.get(key, match.group(0))  # fallback to ${KEY}

    return re.sub(r"\$\{(\w+)\}", replacer, string)


def load_json_parameters(
    config: Dict[str, Any], key: str, fallback: Optional[Dict] = None
) -> Dict:
    """
    Safely load and parse a JSON object from a configuration dictionary.

    Args:
        config (dict): Source configuration.
        key (str): Key to look up in the config whose value should
                  be a JSON string.
        fallback (dict, optional): Optional fallback dict to return
                                  if parsing fails. Defaults to empty dict.

    Returns:
        dict: Parsed JSON dictionary if valid, otherwise fallback or empty dict.
    """
    fallback = fallback or {}

    value = config.get(key)

    if value is None:
        logger.debug(f"Key '{key}' not in config. Using fallback.")
        return fallback

    if isinstance(value, dict):
        # Already a dict, no parsing needed
        return value

    if not isinstance(value, str):
        logger.error(
            f"Expected string or dict for key '{key}',"
            f" got {type(value).__name__}. Using fallback."
        )
        return fallback

    try:
        parsed = json.loads(value)
        if not isinstance(parsed, dict):
            logger.error(
                f"JSON loaded from key '{key}' is not a"
                f" dictionary. Got: {type(parsed).__name__}"
            )
            return fallback
        return parsed
    except json.JSONDecodeError as e:
        logger.error(
            f"JSON decoding failed for key '{key}': {e}. " f"Raw value: {repr(value)}"
        )
        return fallback


def parse_guacamole_url(url, wa_uid=None):
    # Construct JSON according to Guacamole specification
    parser = URLParser()
    url_dict = parser.parse(url)

    # print(url_dict)
    # variables
    protocol = url_dict.get("protocol")
    hostname = url_dict.get("hostname")
    username = url_dict.get("username", None)
    password = url_dict.get("password", None)
    port = url_dict.get("port", None)

    guac_config = {"protocol": protocol, "parameters": {"hostname": hostname}}
    # update the set with default values
    for key, value in DEFAULT_PARAMETERS.items():
        guac_config["parameters"].setdefault(key, value)

    if protocol == "rdp":
        if config.get("RDP_PARAMETERS") is not None:
            logging.debug(f"RDP_PARAMETERS: {config.get('RDP_PARAMETERS')}")
            params = load_json_parameters(config, "RDP_PARAMETERS")
            guac_config["parameters"].update(params)

        # update the set with default values
        for key, value in DEFAULT_RDP_PARAMETERS.items():
            guac_config["parameters"].setdefault(key, value)

    if protocol == "ssh":
        if config.get("SSH_PARAMETERS") is not None:
            logging.debug(f"SSH_PARAMETERS: {config.get('SSH_PARAMETERS')}")
            params = load_json_parameters(config, "SSH_PARAMETERS")
            guac_config["parameters"].update(params)

        # update the set with default values
        for key, value in DEFAULT_SSH_PARAMETERS.items():
            guac_config["parameters"].setdefault(key, value)

    if protocol == "vnc":
        if config.get("VNC_PARAMETERS") is not None:
            logging.debug(f"VNC_PARAMETERS: {config.get('VNC_PARAMETERS')}")
            params = load_json_parameters(config, "VNC_PARAMETERS")
            guac_config["parameters"].update(params)

    if protocol == "telnet":
        if config.get("TELNET_PARAMETERS") is not None:
            logging.debug(f"TELNET_PARAMETERS: {config.get('TELNET_PARAMETERS')}")
            params = load_json_parameters(config, "TELNET_PARAMETERS")
            guac_config["parameters"].update(params)

    if protocol == "KUBERNETES":
        if config.get("KUBERNETES_PARAMETERS") is not None:
            logging.debug(
                f"KUBERNETES_PARAMETERS: {config.get('KUBERNETES_PARAMETERS')}"
            )
            params = load_json_parameters(config, "KUBERNETES_PARAMETERS")
            guac_config["parameters"].update(params)

    if port:
        guac_config["parameters"]["port"] = port
    if username:
        guac_config["parameters"]["username"] = username
    if password:
        guac_config["parameters"]["password"] = password

    # Add any additional query parameters
    guac_config["parameters"].update(url_dict.get("arguments", {}))

    # Check if the path need modification using;
    # recording-path, drive-path, typescript-path

    if guac_config["parameters"].get("pre-recording-path") is not None:
        guac_config["parameters"]["recording-path"] = resolve_path(
            guac_config["parameters"].get("pre-recording-path"),
            guac_config["parameters"].get("recording-path"),
        )

    if guac_config["parameters"].get("pre-drive-path") is not None:
        guac_config["parameters"]["drive-path"] = resolve_path(
            guac_config["parameters"].get("pre-drive-path"),
            guac_config["parameters"].get("drive-path"),
        )

    if guac_config["parameters"].get("pre-typescript-path") is not None:
        guac_config["parameters"]["typescript-path"] = resolve_path(
            guac_config["parameters"].get("pre-typescript-path"),
            guac_config["parameters"].get("typescript-path"),
        )

    guac_fixed_config = fix_newlines(guac_config)

    json = {
        "username": guac_fixed_config["parameters"].get(
            "username", fallback_username()
        ),
        "expires": "0",
        "connections": {f"DA - {fallback_username()}": guac_fixed_config},
    }
    if wa_uid:
        json["username"] = wa_uid

    my_vars = {}
    if wa_uid:
        my_vars["WA_UID"] = wa_uid
    if username:
        my_vars["USERNAME"] = username

    # print(my_vars)

    # print(json)

    json = resolve_vars_in_structure(json, my_vars)

    return json


def fix_newlines(obj):
    if isinstance(obj, dict):
        return {k: fix_newlines(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [fix_newlines(i) for i in obj]
    elif isinstance(obj, str):
        return obj.replace("\\n", "\n")
    else:
        return obj


if __name__ == "__main__":
    """
    Test code...
    """
    setup_logging()
    wa_uid = "wa_jr"
    # Example list of URLs
    urls = [
        "rdp://a@localuser@windows1.example.com/"
        "?abc=${USERNAME}&wa=${WA_UID}&recording-path=/&ab=cd",
        "rdp://a@localuser@windows1.example.com/"
        "?abc=${USERNAME}&wa=${WA_UID}&recording-path=/",
        # Clean RDP URL
        "rdp://a@localuser@windows1.example.com/"
        "?security=rdp&ignore-cert=true&disable-audio=true"
        "&enable-drive=true&drive-path=/mnt/${WA_UID}/usb",
        "rdp://a@localuser@windows1.example.com/"
        "?security=rdp&ignore-cert=true&disable-audio=true"
        "&enable-drive=true&drive-path=mnt/usb/${USERNAME}/abc",
        # Encoded RDP URL
        "rdp%3A%2F%2FAdministrator%3AAbcd1234%40172.16.3.87%2F"
        "?abc%3D%21%40%23%24%25%26def%3D0!@#$%^&*()?<>9",
        # Simple SSH and VNC URLs
        "ssh://ssh-server/",
        "vnc://vnc-server:3399/",
        "vnc://user@vnc-server/",
        "vnc://user@vnc-server:3399/",
        "vnc://user:pass@vnc-server/",
        "vnc://user:pass@vnc-server:3399/",
        # VNC with query parameters
        "vnc://user:pass@vnc-server:3399/?parameters=1232",
        # VNC with tricky password syntax
        "vnc://user:pa@:s@vnc-server:3399/",
        # Long encoded RDP URL split for readability
        "rdp%3A%2F%2FAdministrator%3AAbcd1234%40172.16.3.87%2F"
        "?abc%3D%21%40%23%24%25%26def%3D0!@#$%^&*()?<>9"
        "&def%3D0!@#$%^&*()?<>9"
        "&def%3D0!@#$%^&*()?<>9",
        "ssh://nx3@guacamole/?private-key=-----BEGIN RSA PRIVATE KEY-----\n"
        "MIICXAIBAAKBgQDIT7wmYsnthyqZ9Ua9S9aRz5h06YFVjjmMo8v6fiHaXOxOG12I\n"
        "NB3d5lcNG8XGDkqsJm1SIZ080LzAmI5EN/5tFFxR3ZaJWFVMnNauG3y4rhzmbeAS\n"
        "1Mj9QK0U54u73P17/4un/JaLX3mCZNhhrnSgJIks5tTM/oBM5Bzf41leAwIDAQAB\n"
        "AoGAYyOzh3wVXM4tM43FuSKzy+7nEdYQAPwnV4gqCIwszRp4ih/ZJvREY/MA2qgI\n"
        "NoIUSyepq6CfZd4ZzWiz4OelsA7LMyZ7+wQtrY/qmvIRnOH+8VvuYkxc2QZGbHUL\n"
        "HlioZeC85NO6sV2DFRZ9znR8iDcVzmZmtGeZtCUHTFs0JMECQQDomLNIK8imQ8Ea\n"
        "6/hKIztU/m/Gg+kO1BMkzWWIXAZEaiMwDWyk4MJOirLwoHt+7cnySQpWq0ixibUC\n"
        "kBVW7Gu7AkEA3HdtEZ6kSA0ssMv4XJmNnBR+FOC9Ls6T5gUa91MqyPtpqOymnLGs\n"
        "Na04IJEjwqZ206a5r7krSXlTeqsORxgeWQJBAMSJqwvzuzMKk1Q9SerTRGI4MJis\n"
        "g7S87IQvbni/UahjiuIipcfYBze4qST8Zf3FzduFbk/3oZAqzSGiP/XYBdsCQGoq\n"
        "HFyav1Nu/LFaV4wH6Zhaieh13MQYeEIQ/U5SP00vPE87PnRAXsQuWNPd8JGAZcJA\n"
        "DDThf0XPZfKxQpvbsmkCQEE8qcnSE+XyQIG+hE2wr/dU15qcf6VynEPB1ZUB3SPs\n"
        "qwFY2FO5XdUhmfFG0k9Qr3UgFPquzRpJDqd3cRF3Bdo=\n"
        "-----END RSA PRIVATE KEY-----\n",
    ]

    for url in urls:
        print(f"URL: {url}")
        print(
            json.dumps(
                parse_guacamole_url(url, wa_uid),
                indent=4,
            )
        )
        print("--")
        logger.info(parse_guacamole_url(url, wa_uid))
        print("-------------")

    """
    # Convert each URL and print the JSON output
    parsed_connections = [
        parse_guacamole_url(url) for url in urls if parse_guacamole_url(url)
    ]
    print(json.dumps(parsed_connections, indent=4))
    print("-------------")
    print(
        json.dumps(
            parse_guacamole_url("vnc://user:pass@vnc-server:3399/?parameters=1232"),
            indent=4,
        )
    )
    """
