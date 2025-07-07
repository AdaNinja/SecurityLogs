#!/bin/bash

# Backend API Startup Script
# Starts Node.js application with potential malicious dependencies

set -e

echo "[$(date)] Starting SecurityLogs Backend API..."

# Load environment variables
source /opt/.env 2>/dev/null || true

# Set default values
NODE_ENV=${NODE_ENV:-"production"}
API_PORT=${API_PORT:-3000}
C2_SERVER_URL=${C2_SERVER_URL:-"https://attacker-c2:8443"}

echo "[$(date)] API Configuration:"
echo "  Environment: $NODE_ENV"
echo "  Port: $API_PORT"
echo "  C2 Server: $C2_SERVER_URL"

# Start rsyslog
echo "[$(date)] Starting rsyslog..."
service rsyslog start

# Start tcpdump for network capture
echo "[$(date)] Starting tcpdump..."
tcpdump -i any -w /data/raw/api_traffic.pcap -s 65535 > /dev/null 2>&1 &

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "[$(date)] Installing dependencies..."
    npm install
fi

# Start the Node.js application
echo "[$(date)] Starting Node.js application..."
npm start

# Keep container running
echo "[$(date)] Backend API is ready!"
tail -f /dev/null 