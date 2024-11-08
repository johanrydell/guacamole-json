#!/bin/bash
#
# Start the Guacamole guacd service via Podman

# Default values
PODMAN_IMAGE="${PODMAN_IMAGE:-docker.io/guacamole/guacd:latest}"
PODMAN_NAME="guacd"
BACKGROUND=" -d "

# Check for interactive mode
if [ "$1" = "--interactive" ]; then
    BACKGROUND=""
fi

# Check if Podman is installed
if ! command -v podman &> /dev/null; then
    echo "Podman could not be found, please install it."
    exit 1
fi

# Run the container
echo "Starting Guacamole guacd service with Podman..."
podman run ${BACKGROUND} --rm --replace -p 4822:4822 --name ${PODMAN_NAME} ${PODMAN_IMAGE}

if [ "$1" = "--activate" ]; then
    ./activate-container.sh ${PODMAN_NAME}
fi

