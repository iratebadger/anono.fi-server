#!/bin/bash
# Script to test the server with a simple client

# Ensure we're in the project root
cd "$(dirname "$0")/.."

# Generate client key and CSR
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
  -subj "/C=US/ST=State/L=City/O=Test Client/CN=test-client"

# Submit CSR to server
# Note: For the first certificate, we need to use a different approach
# since we don't have a referrer certificate yet.
# This is for testing only - in production, the bootstrap process would be different.
echo "Requesting certificate from server..."
curl -k -X POST --data-binary @client.csr https://localhost:8443/api/certificate/request > client.crt

# Test server info endpoint
echo -e "\nTesting server info endpoint..."
curl -k --cert client.crt --key client.key https://localhost:8443/api/info

# Get server bin mask
BIN_MASK=$(curl -k --cert client.crt --key client.key -s https://localhost:8443/api/info | grep -o '"bin_mask":"[^"]*"' | cut -d'"' -f4)
echo -e "\nCurrent bin mask: $BIN_MASK"

echo -e "\nTest complete. Generated files:"
echo "  - client.key"
echo "  - client.csr"
echo "  - client.crt"