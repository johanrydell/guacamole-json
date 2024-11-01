import json
import time
from datetime import timedelta

# Define the username
username = "test"

# Get current epoch time in milliseconds
current_epoch = int(time.time() * 1000)

# Add 5 days to the current epoch time
expires = current_epoch + int(timedelta(days=5).total_seconds() * 1000)

# Define the JSON structure
data = {
    "username": username,
    "expires": str(expires),
    "connections": {
        "My Connection": {
            "protocol": "rdp",
            "parameters": {
                "hostname": "10.10.209.63",
                "port": "3389",
                "ignore-cert": "true",
                "recording-path": "/recordings",
                "recording-name": (
                    "My-Connection-${GUAC_USERNAME}-${GUAC_DATE}-${GUAC_TIME}"
                ),
            },
        },
        "My OTHER Connection": {
            "protocol": "rdp",
            "parameters": {
                "hostname": "10.10.209.64",
                "port": "3389",
                "ignore-cert": "true",
                "recording-path": "/recordings",
                "recording-name": (
                    "My-OTHER-Connection-${GUAC_USERNAME}-${GUAC_DATE}-${GUAC_TIME}"
                ),
            },
        },
    },
}

# Write the data to a JSON file
with open("auth.json", "w") as file:
    json.dump(data, file, indent=4)

print(f"JSON file created with expires set to: {expires}")
