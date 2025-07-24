#!/bin/bash
# Build Docker images with host network for better connectivity

set -e

echo "Building Docker images with host network..."

# Build attacker container with host network
echo "Building attacker container..."
docker build --network=host -t securitylogs-attacker:latest -f containers/attacker/Dockerfile .

# Build other containers if needed
echo "Building webapp container..."
docker build --network=host -t securitylogs-webapp:latest -f containers/webapp/Dockerfile .

echo "Building tcpdump container..."
docker build --network=host -t securitylogs-tcpdump:minimal -f containers/tcpdump/Dockerfile .

echo "All containers built successfully!"
echo ""
echo "Available images:"
docker images | grep securitylogs 