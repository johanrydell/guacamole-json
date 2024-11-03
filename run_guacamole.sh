#!/bin/bash
#
# Start the Guacamole service via Podman

# Default values
GUACD_HOSTNAME="${GUACD_HOSTNAME:-guacd}"
PODMAN_IMAGE="${PODMAN_IMAGE:-docker.io/guacamole/guacamole:latest}"
BACKGROUND=" -d "

# Check for interactive mode
if [ "$1" = "--interactive" ]; then
    BACKGROUND=""
fi

# Generate a random secret key
JSON_SECRET_KEY=$(xxd -l 16 -p /dev/urandom)

# Check if Podman is installed
if ! command -v podman &> /dev/null; then
    echo "Podman could not be found, please install it."
    exit 1
fi

# Set environment variables for Podman
PODMAN_ENV=" -e BAN_ENABLED=false -e JSON_ENABLED=true -e GUACD_HOSTNAME=${GUACD_HOSTNAME} -e JSON_SECRET_KEY=${JSON_SECRET_KEY} "

# Run the container
podman run ${BACKGROUND} --rm --replace -p 8080:8080 --name guacamole ${PODMAN_ENV} ${PODMAN_IMAGE}


