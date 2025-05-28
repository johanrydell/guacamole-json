#!/bin/bash

FILE="guacamole-json_latest.tar.gz"
URL="https://us.nexusgroup.com/dl/$FILE"

if [[ ! -f $FILE ]]; then
  echo "File $FILE not found. Downloading from $URL..."
  curl -fLo "$FILE" "$URL" || {
    echo "Error: Failed to download $FILE"
    exit 1
  }
fi

echo "Loading container image from $FILE..."
podman load -i "$FILE"
