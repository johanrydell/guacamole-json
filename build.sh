#!/bin/bash
#
# Start file for Guacamole JSON service
#

# Default values
BUILD_ONLY=false
CONTAINERFILE=""

# Function to print usage
print_usage() {
    echo "Usage: $0 [--prod | --test | --dev] [--build]"
    echo "  --prod       Use Containerfile.prod"
    echo "  --test       Use Containerfile.test"
    echo "  --dev        Use Containerfile.dev"
    echo "  --build      Build the image only"
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
        shift
        ;;
    --dev)
        if [ -n "$CONTAINERFILE" ]; then
            echo "Error: Only one of --prod, --test, or --dev can be specified."
            print_usage
            exit 1
        fi
        CONTAINERFILE="Containerfile.dev"
        shift
        ;;
    --build)
        BUILD_ONLY=true
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
if [[ ! -f project_config.json ]]; then
    echo "project_config.json not found."
    exit 1
fi

PROJECT_NAME=$(jq -r '.name' project_config.json 2>/dev/null)
if [ -z "$PROJECT_NAME" ] || [ "$PROJECT_NAME" == "null" ]; then
    echo "Failed to retrieve project name from project_config.json."
    exit 1
fi

echo "Building image for $PROJECT_NAME using $CONTAINERFILE..."
podman build -f "$CONTAINERFILE" -t "$PROJECT_NAME" .

# If only building, exit after build
if [ "$BUILD_ONLY" = true ]; then
    echo "Building the image has finished."
    exit 0
fi

# Pass remaining arguments to the run script
ARGS=$(echo "$@" | sed 's/--build//g')
./run.sh $ARGS
