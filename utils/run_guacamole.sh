#!/bin/bash
#
# Start the Guacamole (guacamole) service via Podman

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
GUACD_HOSTNAME="${GUACD_HOSTNAME:-guacd}"
CONTAINER_IMAGE="${CONTAINER_IMAGE:-docker.io/guacamole/guacamole:latest}"
CONTAINER_NAME="guacamole"
CONTAINER_PORT="${CONTAINER_PORT:-8080}"
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

# Check if JSON_SECRET_KEY is already set in the environment
if [ -z "${JSON_SECRET_KEY}" ]; then
    if ! command -v xxd &> /dev/null; then
        error "xxd is required for generating a random key but is not installed."
    fi
    JSON_SECRET_KEY=$(xxd -l 16 -p /dev/urandom)
    log "JSON_SECRET_KEY not set in the environment. Generated new key."
else
    log "Using existing JSON_SECRET_KEY from the environment."
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
log "Using port ${CONTAINER_PORT} for Guacamole service."

# Set environment variables for Podman
CONTAINER_ENV=" -e BAN_ENABLED=false -e JSON_ENABLED=true -e GUACD_HOSTNAME=${GUACD_HOSTNAME} -e JSON_SECRET_KEY=${JSON_SECRET_KEY} "

# Run the container
log "Starting the Guacamole (guacamole) container..."
podman run ${BACKGROUND} --rm --replace -p ${CONTAINER_PORT}:8080 --name ${CONTAINER_NAME} ${CONTAINER_ENV} ${CONTAINER_IMAGE}

# Optional activation step
if [ "$1" = "--activate" ]; then
    log "Activating the container..."
    ./activate-container.sh ${CONTAINER_NAME}
fi

log "Guacamole (guacamole) service started successfully."

