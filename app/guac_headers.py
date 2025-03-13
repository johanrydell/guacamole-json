import json
import re
import urllib.parse


def parse_guacamole_url(url):
    # Decode URL
    decoded_url = urllib.parse.unquote(url)

    # Regular expression to parse the URL
    pattern = r"""
        (?P<protocol>rdp|vnc|ssh|telnet|kubernetes)://  # Protocol (rdp, vnc, etc.)
        (?:(?P<user>[^:@/]+)                            # Optional username
        (?: : (?P<password>[^@/]+) )? @ )?              # Optional password
        (?P<host>[^:/?]+)                               # Host (IP or domain)
        (?:: (?P<port>\d+) )?                           # Optional port
        (?: /? \? (?P<query>.+) )?                      # Optional query string
    """

    match = re.match(re.compile(pattern, re.VERBOSE), decoded_url)

    if not match:
        return None

    # Extract components
    protocol = match.group("protocol")
    user = match.group("user")
    password = match.group("password")
    host = match.group("host")
    port = match.group("port")
    query = match.group("query")

    # Convert query parameters into a dictionary
    parameters = {}
    if query:
        for param in query.split("&"):
            key_value = param.split("=", 1)
            if len(key_value) == 2:
                parameters[key_value[0]] = key_value[1]

    # Construct JSON according to Guacamole specification
    guac_config = {"protocol": protocol, "parameters": {"hostname": host}}

    if user:
        guac_config["parameters"]["username"] = user

    if protocol == "rdp":
        default_rdp_parameters = {
            "port": "3389",
            "security": "any",
            "ignore-cert": "true",
            "enable-drive": "true",
            "drive-path": "/tmp/${GUAC_USERNAME}",
            "create-drive-path": "true",
            "enable-printing": "true",
        }
        guac_config["parameters"].update(default_rdp_parameters)

    if port:
        guac_config["parameters"]["port"] = port
    if password:
        guac_config["parameters"]["password"] = password

    # Add any additional query parameters
    guac_config["parameters"].update(parameters)

    f = {
        "username": guac_config["parameters"].get("username", "da-user"),
        "expires": "0",
        "connections": {"DA - Connection": guac_config},
    }

    return f


if __name__ == "__main__":
    """
    Test code...
    """

    # Example list of URLs
    urls = [
        # Clean RDP URL
        "rdp://localuser@windows1.example.com/"
        "?security=rdp&ignore-cert=true&disable-audio=true"
        "&enable-drive=true&drive-path=/mnt/usb",
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
