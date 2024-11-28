#!/bin/bash
#
# Start file for Guacamole JSON service
#

# Default values
BUILD_ONLY=false

# Parse command-line options
for arg in "$@"; do
    case $arg in
	--build*)
	    BUILD_IMAGE=true
	    shift
	    ;;
    esac
done


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

echo "Building image for $PROJECT_NAME..."
podman build -t $PROJECT_NAME .

# Build the Podman image
if [ "$BUILD_IMAGE" = true ]; then
    echo "Building the image has finished"
    exit 0
fi

ARGS=$(echo "$@" | sed 's/--buildonly//g')

./run_app.sh $ARGS


