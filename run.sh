#!/bin/bash

# You must get this from the Guacamole service
JSON_SECRET_KEY=$(podman exec -i guacamole printenv JSON_SECRET_KEY)

# Check the KEY
if [[ "${JSON_SECRET_KEY}" =~ ^[a-fA-F0-9]{32}$ ]]; then
    echo "Valid 32-digit hex value."
else
    echo "Invalid value."
    exit 1  # Exit the script if the value is invalid
fi

PODMAN_ENV=" -e JSON_SECRET_KEY=${JSON_SECRET_KEY} -e JSON_CONFIG_DIR=/json-config "
#PODMAN_ENV=" -e LOG_LEVEL=debug -e JSON_SECRET_KEY=${JSON_SECRET_KEY} -e JSON_CONFIG_DIR=/json-config "
PODMAN_VOL=" -v ./json-config:/json-config "


# Read project name from project_config.json
PROJECT_NAME=$(jq -r '.name' project_config.json)

# Build the Podman image
echo "Building image for $PROJECT_NAME..."
podman build -t $PROJECT_NAME .

# Run the Podman container
echo "Running container for $PROJECT_NAME..."
podman run -d --rm --replace --name $PROJECT_NAME ${PODMAN_ENV} ${PODMAN_VOL} -p 8000:8000 localhost/$PROJECT_NAME:latest
sleep 1
podman logs -f $PROJECT_NAME
