#!/bin/bash

set -e
trap 'echo "Error occurred on line $LINENO. Exiting."; exit 1' ERR

# Logging functions
log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [INFO] $1"
}

error() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') [ERROR] $1" >&2
    exit 1
}

# Constants
HAPROXY_DIR="${HOME}/haproxy-service"
HAPROXY_IMAGE="docker.io/library/haproxy:latest"
HAPROXY_NAME="haproxy"
HAPROXY_TLS_PORT=18443
CERT_FILE="${HAPROXY_DIR}/certificate.crt"
KEY_FILE="${HAPROXY_DIR}/private.key"
PEM_FILE="${HAPROXY_DIR}/haproxy.pem"
CFG_FILE="${HAPROXY_DIR}/haproxy.cfg"

# Variables
SERVER_IP=""
CLEAN_TLS=false
CLEAN_CONFIG=false
FOLLOW_LOGS=false

# Parse arguments
parse_arguments() {
    while [[ "$#" -gt 0 ]]; do
        case $1 in
            --clean)
                CLEAN_CONFIG=true
                ;;
            --clean-tls)
                CLEAN_TLS=true
                ;;
            --clean-all)
                CLEAN_TLS=true
                CLEAN_CONFIG=true
                ;;
            --log)
                FOLLOW_LOGS=true
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
        shift
    done
}

# Retrieve the server IP
get_server_ip() {
    log "Retrieving server IP..."
    SERVER_IP=$(ip route get 1.1.1.1 | awk '{print $7; exit}')
    if [[ -z "${SERVER_IP}" ]]; then
        error "Could not retrieve server IP. Please ensure network connectivity."
    fi
}

# Ensure TLS certificates are in place
setup_tls() {
    log "Setting up TLS certificates..."
    mkdir -p "${HAPROXY_DIR}"

    if [[ "${CLEAN_TLS}" == true || ! -f "${CERT_FILE}" || ! -f "${KEY_FILE}" ]]; then
        log "Generating new self-signed certificate..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout "${KEY_FILE}" \
                -out "${CERT_FILE}" \
                -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=localhost"
    fi

    log "Creating combined PEM file for HAProxy..."
    cat "${CERT_FILE}" "${KEY_FILE}" > "${PEM_FILE}"
}

# Pull the HAProxy image if it is not available locally
check_and_pull_image() {
    log "Checking for HAProxy image..."
    if ! podman images --format "{{.Repository}}:{{.Tag}}" | grep -q "^${HAPROXY_IMAGE}$"; then
        log "HAProxy image not found locally. Pulling the image..."
        podman pull "${HAPROXY_IMAGE}" || error "Failed to pull the HAProxy image."
    else
        log "HAProxy image found locally."
    fi
}

# Create the HAProxy configuration file
create_config() {
    get_server_ip

    if [[ "${CLEAN_CONFIG}" == true || ! -f "${CFG_FILE}" ]]; then
        log "Creating HAProxy configuration file..."
        cat <<EOL > "${CFG_FILE}"
global
    log stdout format raw local0 info
    ssl-default-bind-options no-sslv3
    ssl-default-bind-ciphers HIGH:!SSLv3:!TLSv1

defaults
    log     global
    option  httplog
    option  dontlognull
    timeout connect 5000ms
    timeout client  50000ms
    timeout server  50000ms

frontend https_front
    bind *:${HAPROXY_TLS_PORT} ssl crt /etc/ssl/haproxy.pem
    mode http
    default_backend guacamole_backend

backend guacamole_backend
    mode http
    server guacamole ${SERVER_IP}:8080
EOL
        log "HAProxy configuration created at ${CFG_FILE}."
    else
        log "HAProxy configuration file already exists. Skipping creation."
    fi
}

# Run the HAProxy container
run_container() {
    log "Starting HAProxy container..."

    # Stop any existing container with the same name
    if podman ps -a --format "{{.Names}}" | grep -q "^${HAPROXY_NAME}$"; then
        log "Stopping and removing existing HAProxy container..."
        podman rm -f ${HAPROXY_NAME} || error "Failed to remove existing HAProxy container."
    fi

    # Run the container
    podman run --rm --replace --name ${HAPROXY_NAME} -d -p ${HAPROXY_TLS_PORT}:${HAPROXY_TLS_PORT} \
           -v "${CFG_FILE}:/usr/local/etc/haproxy/haproxy.cfg:ro" \
           -v "${PEM_FILE}:/etc/ssl/haproxy.pem:ro" \
           ${HAPROXY_IMAGE}

    log "HAProxy is running with TLS on port ${HAPROXY_TLS_PORT}."

    if [[ "${FOLLOW_LOGS}" == true ]]; then
        log "Following logs for the HAProxy container..."
        podman logs -f ${HAPROXY_NAME}
    fi
}

# Main execution flow
main() {
    parse_arguments "$@"
    setup_tls
    check_and_pull_image
    create_config
    run_container
}

main "$@"



