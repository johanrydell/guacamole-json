import json
import os
import re
import time
from typing import Any, Dict
from urllib.parse import unquote

from config import load_config

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


def parse_guacamole_url(url, wa_uid=None):
    # Construct JSON according to Guacamole specification
    parser = URLParser()
    url_dict = parser.parse(url)

    print(url_dict)
    # variables
    protocol = url_dict.get("protocol")
    hostname = url_dict.get("hostname")
    username = url_dict.get("username", None)
    password = url_dict.get("password", None)
    port = url_dict.get("port", None)

    guac_config = {"protocol": protocol, "parameters": {"hostname": hostname}}

    if protocol == "rdp":
        default_rdp_parameters = {
            "port": "3389",
            "security": "any",
            "ignore-cert": "true",
            "enable-drive": "true",
            "drive-path": "",
            "create-drive-path": "true",
            "enable-printing": "true",
        }
        guac_config["parameters"].update(default_rdp_parameters)

    if port:
        guac_config["parameters"]["port"] = port
    if username:
        guac_config["parameters"]["username"] = username
    if password:
        guac_config["parameters"]["password"] = password

    # Add any additional query parameters
    guac_config["parameters"].update(url_dict.get("arguments", {}))

    drive_path = resolve_path(
        config.get("PRE_DRIVE_PATH", ""),
        guac_config["parameters"].get("drive-path", ""),
    )

    recording_path = resolve_path(
        config.get("PRE_RECORDING_PATH", ""),
        guac_config["parameters"].get("recording-path", ""),
    )

    typescript_path = resolve_path(
        config.get("PRE_TYPESCRIPT_PATH", ""),
        guac_config["parameters"].get("typescript-path", ""),
    )

    if drive_path:
        guac_config["parameters"]["drive-path"] = drive_path
    if recording_path:
        guac_config["parameters"]["recording-path"] = recording_path
    if typescript_path:
        guac_config["parameters"]["typescript-path"] = typescript_path

    json = {
        "username": guac_config["parameters"].get("username", fallback_username()),
        "expires": "0",
        "connections": {"DA - Connection": guac_config},
    }
    if wa_uid:
        json["username"] = wa_uid

    my_vars = {}
    if wa_uid:
        my_vars["WA_UID"] = wa_uid
    if username:
        my_vars["USERNAME"] = username

    print(my_vars)

    print(json)

    json = resolve_vars_in_structure(json, my_vars)

    return json


if __name__ == "__main__":
    """
    Test code...
    """
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
    ]

    for url in urls:
        print(f"URL: {url}")
        print(
            json.dumps(
                parse_guacamole_url(url, wa_uid),
                indent=4,
            )
        )
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
