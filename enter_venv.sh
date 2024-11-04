#!/bin/bash

# Determine the directory of the script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check if the script is sourced by comparing $0
if [[ "$0" == "$BASH_SOURCE" ]]; then
    echo "Please run this script with 'source' to activate the virtual environment."
    echo "Usage: source $0"
    exit 1  # Exit the script since it was run directly
else
    echo "Checking for virtual environment..."

    # Create the virtual environment if it doesn't exist
    if [ ! -d "$SCRIPT_DIR/venv" ]; then
        echo "Virtual environment not found. Creating one..."
        python3 -m venv "$SCRIPT_DIR/venv"
    fi

    echo "Activating the virtual environment..."
    source "$SCRIPT_DIR/venv/bin/activate"

    # Install requirements
    if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
        echo "Installing dependencies..."
        pip install -r "$SCRIPT_DIR/requirements.txt"
    else
        echo "requirements.txt not found!"
    fi

    # Check if in a Git repository and if .pre-commit-config.yaml exists
    if [ -d "$SCRIPT_DIR/.git" ] && [ -f "$SCRIPT_DIR/.pre-commit-config.yaml" ]; then
        echo "Git repository and .pre-commit-config.yaml found. Setting up pre-commit hooks..."

        # Ensure pre-commit is installed
        pip install pre-commit

        # Install pre-commit hooks
        pre-commit install

        # Optional: Run pre-commit on all files
        echo "Running pre-commit on all files for the first time..."
        pre-commit run --all-files
    else
        echo "No Git repository or .pre-commit-config.yaml file found. Skipping pre-commit setup."
    fi
fi
