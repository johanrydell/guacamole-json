#!/bin/bash

# Check if the script is sourced by comparing $0
if [[ "$0" == "$BASH_SOURCE" ]]; then
    echo "Please run this script with 'source' to activate the virtual environment."
    echo "Usage: source $0"
    exit 1  # Exit the script since it was run directly
else
    echo "Activating the virtual environment..."
    source /home/johanr/guac-json/venv/bin/activate
    
    # Install requirements
    if [ -f "/home/johanr/guac-json/requirements.txt" ]; then
        echo "Installing dependencies..."
        pip install -r /home/johanr/guac-json/requirements.txt
    else
        echo "requirements.txt not found!"
    fi
fi
