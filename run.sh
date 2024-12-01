#!/bin/bash
#
# Start file for Guacamole JSON service
#

# Logging functions
log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO] $1"
}

error() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [ERROR] $1" >&2
    exit 1
}

# Default values
BACKGROUND=" -d "
SHOW_LOGS=false
BUILD_IMAGE=false
ACTIVATE_SYSTEMD=false
JSON_DIR="${HOME}/guacamole-json-service/files"
GUACAMOLE_URL=http://172.16.2.81:8080
CONTAINER_IMAGE=localhost/guacamole-json:latest
CONTAINER_NAME=guacamole-json
SSO="true"
CUSTOM_KEY=""

# TLS
TLS_LOCAL_DIR="${HOME}/certs"
TLS_MOUNT="/certs"
TLS_CERT="${TLS_MOUNT}/fullchain.pem"
TLS_KEY="${TLS_MOUNT}/privkey.pem"
TLS_ENV=""


# Parse command-line options
for arg in "$@"; do
    case $arg in
        --interactive)
            BACKGROUND=""
            shift
            ;;
        --log*)
            SHOW_LOGS=true
            shift
            ;;
        --activate)
            ACTIVATE_SYSTEMD=true
            shift
            ;;
        --debug)
            LOG=" -e LOG_LEVEL=DEBUG "
            shift
            ;;
        --no-sso)
            SSO="false"
            shift
            ;;
        --key=*)
            CUSTOM_KEY="${arg#*=}"
            if [[ ! "${CUSTOM_KEY}" =~ ^[a-fA-F0-9]{32}$ ]]; then
                error "--key must be a 32-character hexadecimal value."
            fi
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --key=<VALUE>       Provide a custom 32-character hex key for the JSON service."
            echo "  --interactive       Run the container interactively."
            echo "  --log               Show container logs after starting."
            echo "  --activate          Activate systemd service after starting the container."
            echo "  --debug             Set log level to DEBUG."
            echo "  --no-sso            Disable single sign-on mode."
            echo "  --help, -h          Show this help message."
            exit 0
            ;;
        *)
            error "Unknown option: $arg"
            ;;
    esac
done

# Stop systemd function
stop_systemd (){
    log "Stopping existing container or service..."
    local is_running=$(podman ps --format "{{.Names}}" | grep -c "^${CONTAINER_NAME}$")

    if [ -r "$SYSTEMD/${CONTAINER_NAME}.service" ] && [ "$is_running" -ne 0 ]; then
        systemctl --user stop "${CONTAINER_NAME}.service"
        is_running=$(podman ps --format "{{.Names}}" | grep -c "^${CONTAINER_NAME}$")
    fi

    if [ "$is_running" -ne 0 ]; then
        podman stop "${CONTAINER_NAME}"
    fi

    local is_present=$(podman ps -a --format "{{.Names}}" | grep -c "^${CONTAINER_NAME}$")
    if [ "$is_present" -ne 0 ]; then
        podman rm "${CONTAINER_NAME}"
    fi
}

# Activate systemd function
activate_systemd (){
    if [ -x "./utils/activate-container.sh" ]; then
        log "Activating systemd service for ${CONTAINER_NAME}..."
        ./utils/activate-container.sh ${CONTAINER_NAME}
    fi
}

# Retrieve JSON_SECRET_KEY
if [ -n "$CUSTOM_KEY" ]; then
    JSON_SECRET_KEY="$CUSTOM_KEY"
    log "Using provided JSON_SECRET_KEY."
else
    log "Retrieving JSON_SECRET_KEY from the Guacamole container..."
    JSON_SECRET_KEY=$(podman exec -i guacamole printenv JSON_SECRET_KEY 2>/dev/null)
    if [ -z "$JSON_SECRET_KEY" ]; then
        error "Failed to retrieve JSON_SECRET_KEY from the Guacamole container."
    fi
    log "Successfully retrieved JSON_SECRET_KEY."
fi

# Validate JSON_SECRET_KEY format
if [[ ! "${JSON_SECRET_KEY}" =~ ^[a-fA-F0-9]{32}$ ]]; then
    error "Invalid JSON_SECRET_KEY format."
fi

# Podman environment and volume options
mkdir -p ${JSON_DIR}
CONTAINER_ENV=" -e JSON_SECRET_KEY=${JSON_SECRET_KEY} -e JSON_DIR=/json -e GUACAMOLE_URL=${GUACAMOLE_URL} ${LOG} -e BASIC=${SSO} "
CONTAINER_VOL=" -v ${JSON_DIR}:/json "

# Verify TLS certificates exist
if [ -f "${TLS_LOCAL_DIR}/fullchain.pem" ] && [ -f "${TLS_LOCAL_DIR}/privkey.pem" ]; then
    log "Using provided certificates and key from ${TLS_LOCAL_DIR}."
    TLS_ENV=" -e TLS_CERT=${TLS_CERT} -e TLS_KEY=${TLS_KEY} -v ${TLS_LOCAL_DIR}:${TLS_MOUNT}:ro "
else
    log "TLS certificates not found in ${TLS_LOCAL_DIR}."
fi


# Run the Podman container
log "Stopping any old container ${CONTAINER_NAME}..."
stop_systemd
log "Running container ${CONTAINER_NAME}..."
podman run ${BACKGROUND} --rm --replace --name ${CONTAINER_NAME} ${TLS_ENV} ${CONTAINER_ENV} ${CONTAINER_VOL} -p 8000:8000 ${CONTAINER_IMAGE} || error "Failed to start container ${CONTAINER_NAME}."

# Activate systemd if requested
if [ "$ACTIVATE_SYSTEMD" = true ] && [ ! -z "${BACKGROUND}" ]; then
    activate_systemd
fi

# Display logs if --log is specified
if [ "$SHOW_LOGS" = true ] && [ ! -z "${BACKGROUND}" ]; then
    log "Displaying logs for ${CONTAINER_NAME}..."
    podman logs -f $CONTAINER_NAME
fi
