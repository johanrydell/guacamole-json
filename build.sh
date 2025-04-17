#!/bin/bash
#
# Optimized Build Script for Guacamole JSON service (No jq dependency)
#

set -e  # Exit on error

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
    echo "  --version    Tag the build with this instead of 'latest'"
    exit 1
}

# Argument parsing
while [[ $# -gt 0 ]]; do
    case "$1" in
    --prod)
        [[ -n "$CONTAINERFILE" ]] && { echo "Error: Only one of --prod, --test, or --dev can be specified."; print_usage; }
        CONTAINERFILE="Containerfile.prod"
        ;;
    --test)
        [[ -n "$CONTAINERFILE" ]] && { echo "Error: Only one of --prod, --test, or --dev can be specified."; print_usage; }
        CONTAINERFILE="Containerfile.test"
        BUILD_TYPE=""
        ;;
    --dev)
        [[ -n "$CONTAINERFILE" ]] && { echo "Error: Only one of --prod, --test, or --dev can be specified."; print_usage; }
        CONTAINERFILE="Containerfile.dev"
        BUILD_TYPE=""
        ;;
    --version=*)
        VERSION="${1#*=}"
        ;;
    *)
        echo "Unknown argument: $1"
        print_usage
        ;;
    esac
    shift
done

# Validate that a container file was chosen
[[ -z "$CONTAINERFILE" ]] && { echo "Error: You must specify one of --prod, --test, or --dev."; print_usage; }

# Validate that the Containerfile exists
[[ ! -f "$CONTAINERFILE" ]] && { echo "Error: $CONTAINERFILE not found."; exit 1; }

# Validate project config JSON
[[ ! -f "$PROJECT_CONFIG" ]] && { echo "Error: $PROJECT_CONFIG not found."; exit 1; }

# Parse project name (pure Bash, no jq)
PROJECT_NAME=$(grep -o '"name": *"[^"]*"' "$PROJECT_CONFIG" | awk -F'"' '{print $4}')

# Ensure a valid project name was extracted
[[ -z "$PROJECT_NAME" ]] && { echo "Error: Failed to retrieve project name from $PROJECT_CONFIG."; exit 1; }

echo "🚀 Building image for $PROJECT_NAME using $CONTAINERFILE..."

# Optimize Podman build
podman build --layers --format docker \
    -f "$CONTAINERFILE" \
    --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    --build-arg BUILD_VERSION="${BUILD_TYPE}${VERSION}" \
    -t "$PROJECT_NAME:${BUILD_TYPE}${VERSION}" .

echo "✅ Build completed successfully!"
