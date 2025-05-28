#!/bin/bash
#
# Start the Guacamole (guacd) service via Podman

set -e
trap 'echo "Error occurred on line $LINENO. Exiting."; exit 1' ERR

# Logging functions
log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO] $1"
}

error() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [ERROR] $1" >&2
    exit 1
}

# Default values
CONTAINER_IMAGE="${CONTAINER_IMAGE:-docker.io/guacamole/guacd:1.5.5}"
CONTAINER_NAME="guacd"
CONTAINER_PORT="${CONTAINER_PORT:-4822}"
BACKGROUND=" -d "

# Help message
if [ "$1" = "--help" ]; then
    echo "Usage: $0 [--interactive|--activate]"
    echo "Options:"
    echo "  --interactive  Run the container in the foreground"
    echo "  --activate     Activate the container after startup"
    exit 0
fi

# Check for interactive mode
if [ "$1" = "--interactive" ]; then
    BACKGROUND=""
fi

# Check for Podman
if ! command -v podman &> /dev/null; then
    error "Podman could not be found, please install it."
fi

# Check if the container image exists locally
if ! podman images --format "{{.Repository}}:{{.Tag}}" | grep -q "${CONTAINER_IMAGE}"; then
    log "Image ${CONTAINER_IMAGE} not found locally. Pulling the image..."
    podman pull "${CONTAINER_IMAGE}" || error "Failed to pull the image ${CONTAINER_IMAGE}."
else
    log "Image ${CONTAINER_IMAGE} found locally."
fi

# Check and clean up existing container
if podman ps -a --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}\$"; then
    log "Stopping and removing existing container: ${CONTAINER_NAME}"
    podman rm -f ${CONTAINER_NAME} || error "Failed to remove existing container."
fi

# Check port availability
while lsof -i:${CONTAINER_PORT} &> /dev/null; do
    log "Port ${CONTAINER_PORT} is in use. Trying next port."
    CONTAINER_PORT=$((CONTAINER_PORT+1))
done
log "Using port ${CONTAINER_PORT} for Guacamole (guacd) service."

# Set environment variables for Podman
CONTAINER_ENV=""

# Run the container
log "Starting the Guacamole (guacd) container..."
podman run ${BACKGROUND} --rm --replace -p ${CONTAINER_PORT}:4822 --name ${CONTAINER_NAME} ${CONTAINER_ENV} ${CONTAINER_IMAGE}

# Optional activation step
if [ "$1" = "--activate" ]; then
    log "Activating the container..."
    ./activate-container.sh ${CONTAINER_NAME}
fi

log "Guacamole (guacd) service started successfully."

