#!/bin/bash

# Set the directory
HAPROXY_DIR="${HOME}/haproxy-service"
HAPROXY_IMAGE="docker.io/library/haproxy:latest"
HAPROXY_TLS_PORT=18443

# Set file paths
CERT_FILE="${HAPROXY_DIR}/certificate.crt"
KEY_FILE="${HAPROXY_DIR}/private.key"
PEM_FILE="${HAPROXY_DIR}/haproxy.pem"
CFG_FILE="${HAPROXY_DIR}/haproxy.cfg"


get_server_ip() {
    ip route get 1.1.1.1 | awk '{print $7; exit}'
}

# Create the directory if it doesn't exist
mkdir -p "${HAPROXY_DIR}"

# Step 2: Create SSL files if they don't exist
if [[ ! -f "${CERT_FILE}" ]]; then
    echo "Generating self-signed certificate..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "${KEY_FILE}" \
        -out "${CERT_FILE}" \
        -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=localhost"
fi

# Step 3: Create haproxy.pem from certificate.crt and private.key
cat "${CERT_FILE}" "${KEY_FILE}" > "${PEM_FILE}"

# Step 4: Get the Podman network IP address
PODMAN_NETWORK_IP=$(get_server_ip)

if [[ -z "${PODMAN_NETWORK_IP}" ]]; then
    echo "Error: Could not retrieve Podman network IP."
    exit 1
fi

echo "Podman network IP: ${PODMAN_NETWORK_IP}"

# Step 5: Create haproxy.cfg if it doesn't exist
if [[ "$1" == "--clean" || ! -f "${CFG_FILE}" ]]; then
    echo "Creating HAProxy configuration..."
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
    server guacamole ${PODMAN_NETWORK_IP}:8080
EOL
fi

# Step 6: Run the container using Podman
echo "Starting HAProxy container..."
podman run --rm --replace --name haproxy -d -p ${HAPROXY_TLS_PORT}:${HAPROXY_TLS_PORT} \
    -v "${HAPROXY_DIR}/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro" \
    -v "${HAPROXY_DIR}/haproxy.pem:/etc/ssl/haproxy.pem:ro" \
    ${HAPROXY_IMAGE}

echo "HAProxy is running with TLS on port ${HAPROXY_TLS_PORT}."
