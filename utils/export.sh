#!/bin/bash

# Usage:
#   ./export.sh             → Exports 'latest' and compresses
#   ./export.sh v1.2        → Exports tag 'v1.2' and compresses
#   ./export.sh --no-gzip   → Exports 'latest' without compression
#   ./export.sh v1.2 --no-gzip → Exports 'v1.2' without compression

# Default values
TAG="latest"
DO_GZIP=true

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --no-gzip)
            DO_GZIP=false
            ;;
        *)
            TAG="$arg"
            ;;
    esac
done

TAR_FILE="guacamole-json_${TAG}.tar"
IMAGE_NAME="localhost/guacamole-json:${TAG}"

# Check if the image exists
if ! podman image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "Error: Image '${IMAGE_NAME}' not found."
    exit 1
fi

echo "Exporting image '${IMAGE_NAME}' to '${TAR_FILE}'..."
podman save -o "$TAR_FILE" "$IMAGE_NAME"

if [ $? -ne 0 ]; then
    echo "Error: Failed to export the image."
    exit 1
fi

if [ "$DO_GZIP" = true ]; then
    echo "Compressing to '${TAR_FILE}.gz'..."
    gzip "$TAR_FILE"
    echo "Compression done."
else
    echo "Skipping compression as '--no-gzip' was specified."
fi

echo "Export completed."


