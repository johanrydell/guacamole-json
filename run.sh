#!/bin/bash
#
# Start file for Guacamole JSON service
#

# Default values
BACKGROUND=" -d "
SHOW_LOGS=false
BUILD_IMAGE=false
JSON_CONFIG_DIR="./json-config"


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
	    --build*)
	        BUILD_IMAGE=true
	        shift
	        ;;
        *)
            echo "Unknown option: $arg"
            exit 1
            ;;
    esac
done

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
PODMAN_ENV=" -e JSON_SECRET_KEY=${JSON_SECRET_KEY} -e JSON_CONFIG_DIR=/json-config "
PODMAN_VOL=" -v ${JSON_CONFIG_DIR}:/json-config "

# Check if project_config.json exists and parse the project name
if [[ ! -f project_config.json ]]; then
    echo "project_config.json not found."
    exit 1
fi

PROJECT_NAME=$(jq -r '.name' project_config.json 2>/dev/null)
if [ -z "$PROJECT_NAME" ] || [ "$PROJECT_NAME" == "null" ]; then
    echo "Failed to retrieve project name from project_config.json."
    exit 1
fi

# Build the Podman image
if [ "$BUILD_IMAGE" = true ]; then
    echo "Building image for $PROJECT_NAME..."
    podman build -t $PROJECT_NAME .
fi

# Run the Podman container
echo "Running container for $PROJECT_NAME..."
podman run ${BACKGROUND} --rm --replace --name $PROJECT_NAME ${PODMAN_ENV} ${PODMAN_VOL} -p 8000:8000 localhost/$PROJECT_NAME:latest

# Display logs if --log is specified
if [ "$SHOW_LOGS" = true ] && [ ! -z "${BACKGROUND}" ] ; then
    podman logs -f $PROJECT_NAME
fi
