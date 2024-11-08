#!/bin/bash
#
# Start file for Guacamole JSON service
#

# Default values
BACKGROUND=" -d "
SHOW_LOGS=false
BUILD_IMAGE=false
ACTIVATE_SYSTEMD=false
JSON_CONFIG_DIR="./json-config"
GUACAMOLE_URL=http://172.16.2.127:8080
CONTAINER_IMAGE=localhost/guacamole-json:latest
CONTAINER_NAME=guacamole-json

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
	    ;;
	--debug)
	    LOG=" -e LOG_LEVEL=DEBUG "
	    ;;
        *)
            echo "Unknown option: $arg"
            exit 1
            ;;
    esac
done


stop_systemd (){
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

activate_systemd (){
    ./activate-container.sh ${CONTAINER_NAME}
}


# Retrieve JSON_SECRET_KEY from the running Guacamole container
JSON_SECRET_KEY=$(podman exec -i guacamole printenv JSON_SECRET_KEY 2>/dev/null)
if [ -z "$JSON_SECRET_KEY" ]; then
    echo "Failed to retrieve JSON_SECRET_KEY from the Guacamole container."
    exit 1
fi

# Check the KEY format
if [[ "${JSON_SECRET_KEY}" =~ ^[a-fA-F0-9]{32}$ ]]; then
    echo "Valid 32-digit hex value."
else
    echo "Invalid JSON_SECRET_KEY format."
    exit 1
fi

# Podman environment and volume options
mkdir -p ${JSON_CONFIG_DIR}
CONTAINER_ENV=" -e JSON_SECRET_KEY=${JSON_SECRET_KEY} -e JSON_CONFIG_DIR=/json-config -e GUACAMOLE_URL=${GUACAMOLE_URL} ${LOG} "
CONTAINER_VOL=" -v ${JSON_CONFIG_DIR}:/json-config "

# Run the Podman container
echo "Running container for $PROJECT_NAME..."
stop_systemd
podman run ${BACKGROUND} --rm --replace --name ${CONTAINER_NAME} ${CONTAINER_ENV} ${CONTAINER_VOL} -p 8000:8000 ${CONTAINER_IMAGE}

if [ "$ACTIVATE_SYSTEMD" = true ] && [ ! -z "${BACKGROUND}" ] ; then
    activate_systemd
fi
    
# Display logs if --log is specified
if [ "$SHOW_LOGS" = true ] && [ ! -z "${BACKGROUND}" ] ; then
    podman logs -f $CONTAINER_NAME
fi
