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
SHOW_LOGS=false
ACTIVATE_SYSTEMD=false
CONFIG_LOCAL_DIR="${HOME}/guacamole-json-service/files"
CONFIG_DIR="/json"
GUACAMOLE_URL=http://guacamole:8080
SSO="true"
CUSTOM_KEY=""
CONTAINER_PORT=8000
CONTAINER_NAME=guacamole-json
CONTAINER_IMAGE=localhost/guacamole-json:latest
BACKGROUND=" -d "


# TLS
TLS_LOCAL_DIR="${HOME}/guacamole-json-service/tls"
TLS_DIR="/tls"
TLS_CERT="fullchain.pem"
TLS_KEY="privkey.pem"
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


set_latest_image (){
    # Get the list of matching images with their full names (repository:tag)
    local CONTAINER_IMAGES=$(podman images --format "{{.Repository}}:{{.Tag}}" | grep "$CONTAINER_NAME")
    
    # If no matching images are found, exit with an error
    if [[ -z "$CONTAINER_IMAGES" ]]; then
	error "No images found for $CONTAINER_NAME"
	error "Please pull the image for: $CONTAINER_IMAGE"
	exit 1
    else
	log "Using container image: $CONTAINER_IMAGE"
    fi
    
    # If only one image is found, handle it directly
    if [[ $(echo "$CONTAINER_IMAGES" | wc -l) -eq 1 ]]; then
	CONTAINER_IMAGE="$CONTAINER_IMAGES"
    else
	# Check if 'latest' exists and return it if found
	if echo "$CONTAINER_IMAGES" | grep -q ":latest"; then
            CONTAINER_IMAGE=$(echo "$CONTAINER_IMAGES" | grep ":latest")
	else
            # Extract numeric tags, sort them, and find the highest version
            CONTAINER_IMAGE=$(echo "$CONTAINER_IMAGES" | grep -Eo '^[^:]+:[0-9]+\.[0-9]+(\.[0-9]+)?' | sort -t: -k2,2V | tail -n 1)
	fi
    fi
}




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
mkdir -p ${CONFIG_LOCAL_DIR}
CONTAINER_ENV=" -e JSON_SECRET_KEY=${JSON_SECRET_KEY} -e CONFIG_DIR=${CONFIG_DIR} -e GUACAMOLE_URL=${GUACAMOLE_URL} ${LOG} -e SSO=${SSO} "
CONTAINER_VOL=" -v ${CONFIG_LOCAL_DIR}:${CONFIG_DIR} "

# Verify TLS certificates exist
mkdir -p ${TLS_LOCAL_DIR}
echo "podman unshare chown 0:0 *" > "${TLS_LOCAL_DIR}/help.txt"
if [ -f "${TLS_LOCAL_DIR}/${TLS_CERT}" ] && [ -f "${TLS_LOCAL_DIR}/${TLS_KEY}" ]; then
    log "Using provided certificates and key from ${TLS_LOCAL_DIR}."
    TLS_ENV=" -e TLS_DIR=${TLS_DIR} -e TLS_CERT=${TLS_CERT} -e TLS_KEY=${TLS_KEY} -v ${TLS_LOCAL_DIR}:${TLS_DIR}:ro --userns=keep-id "
else
    log "TLS certificates not found. Mounting ${TLS_LOCAL_DIR} as Read/Write."
    TLS_ENV=" -e TLS_DIR=${TLS_DIR} -e TLS_CERT=${TLS_CERT} -e TLS_KEY=${TLS_KEY} -v ${TLS_LOCAL_DIR}:${TLS_DIR}:rw --userns=keep-id "
fi


# Run the Podman container
set_latest_image
log "Stopping any old container ${CONTAINER_NAME}..."
stop_systemd
log "Running container ${CONTAINER_NAME}..."
podman run ${BACKGROUND} --rm --replace --name ${CONTAINER_NAME} ${TLS_ENV} ${CONTAINER_ENV} ${CONTAINER_VOL} -p ${CONTAINER_PORT}:8000 ${CONTAINER_IMAGE} || error "Failed to start container ${CONTAINER_NAME}."

# Activate systemd if requested
if [ "$ACTIVATE_SYSTEMD" = true ] && [ ! -z "${BACKGROUND}" ]; then
    activate_systemd
fi

# Display logs if --log is specified
if [ "$SHOW_LOGS" = true ] && [ ! -z "${BACKGROUND}" ]; then
    log "Displaying logs for ${CONTAINER_NAME}..."
    podman logs -f $CONTAINER_NAME
fi
