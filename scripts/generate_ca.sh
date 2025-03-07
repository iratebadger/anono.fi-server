#!/bin/bash
# Script to generate CA certificate and key for development

# Ensure we're in the project root
cd "$(dirname "$0")/.."

# Create certs directory if it doesn't exist
mkdir -p certs

# Generate private key
openssl genrsa -out certs/ca.key 4096

# Generate CA certificate
openssl req -x509 -new -nodes -key certs/ca.key -sha256 -days 3650 -out certs/ca.crt \
  -subj "/C=US/ST=State/L=City/O=Secure Messaging POC/CN=Secure Messaging CA"

echo "CA certificate and key generated in the certs directory:"
echo "  - certs/ca.key"
echo "  - certs/ca.crt"