#!/bin/bash
#
# Build file for Guacamole JSON service
#

# Default values
BUILD_TYPE=""
CONTAINERFILE=""
VERSION="latest"
PROJECT_CONFIG="project_config.json"

# Function to print usage
print_usage() {
    echo "Usage: $0 [--prod | --test | --dev] [--version=VERSION]"
    echo "  --prod       Use Containerfile.prod"
    echo "  --test       Use Containerfile.test"
    echo "  --dev        Use Containerfile.dev"
    echo "  --version    Tag the build with this instread of 'latest'"
}

# Parse command-line options
for arg in "$@"; do
    case $arg in
    --prod)
        if [ -n "$CONTAINERFILE" ]; then
            echo "Error: Only one of --prod, --test, or --dev can be specified."
            print_usage
            exit 1
        fi
        CONTAINERFILE="Containerfile.prod"
        shift
        ;;
    --test)
        if [ -n "$CONTAINERFILE" ]; then
            echo "Error: Only one of --prod, --test, or --dev can be specified."
            print_usage
            exit 1
        fi
        CONTAINERFILE="Containerfile.test"
        BUILD_TYPE="test_"
        shift
        ;;
    --dev)
        if [ -n "$CONTAINERFILE" ]; then
            echo "Error: Only one of --prod, --test, or --dev can be specified."
            print_usage
            exit 1
        fi
        CONTAINERFILE="Containerfile.dev"
        BUILD_TYPE="dev_"
        shift
        ;;
    --version=*)
        VERSION="${arg#*=}"
        shift
        ;;
    esac
done

# Validate that a container file was chosen
if [ -z "$CONTAINERFILE" ]; then
    echo "Error: You must specify one of --prod, --test, or --dev."
    print_usage
    exit 1
fi

# Check if the specified Containerfile exists
if [[ ! -f "$CONTAINERFILE" ]]; then
    echo "Error: $CONTAINERFILE not found. Ensure the file exists."
    exit 1
fi

# Check if project_config.json exists and parse the project name
if [[ ! -f "${PROJECT_CONFIG}" ]]; then
    echo "${PROJECT_CONFIG} not found."
    exit 1
fi

PROJECT_NAME=$(jq -r '.name' ${PROJECT_CONFIG} 2>/dev/null)
if [ -z "$PROJECT_NAME" ] || [ "$PROJECT_NAME" == "null" ]; then
    echo "Failed to retrieve project name from ${PROJECT_CONFIG}."
    exit 1
fi

echo "Building image for $PROJECT_NAME using $CONTAINERFILE..."
podman build -f "$CONTAINERFILE" --build-arg \
    BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    --build-arg BUILD_VERSION="${BUILD_TYPE}${VERSION}" -t "$PROJECT_NAME:${BUILD_TYPE}${VERSION}" .

echo "Building the image has finished."
