#!/bin/bash
# Build only attacker container with host network for package installation
# This maintains runtime network isolation while solving build-time connectivity issues

set -e

echo "Building attacker container with host network for package installation..."

# Build attacker container with host network
docker build --network=host -t securitylogs-attacker:latest -f containers/attacker/Dockerfile .

echo "Attacker container built successfully!"
echo ""
echo "Note: Runtime containers will still use isolated network for security experiments"
echo "Available images:"
docker images | grep securitylogs-attacker 