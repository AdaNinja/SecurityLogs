#!/bin/bash

# C2 Server Startup Script
# Supports multiple C2 protocols for different scenarios

set -e

echo "[$(date)] Starting SecurityLogs C2 Server..."

# Load environment variables
source /opt/.env 2>/dev/null || true

# Set default values
C2_PROTOCOL=${C2_PROTOCOL:-"http"}
C2_PORT=${C2_PORT:-8080}
SCENARIO_TYPE=${SCENARIO_TYPE:-"c2-server"}

echo "[$(date)] C2 Configuration:"
echo "  Protocol: $C2_PROTOCOL"
echo "  Port: $C2_PORT"
echo "  Scenario: $SCENARIO_TYPE"

# Start rsyslog
echo "[$(date)] Starting rsyslog..."
service rsyslog start

# Start tcpdump for network capture
echo "[$(date)] Starting tcpdump..."
tcpdump -i any -w /data/raw/c2_traffic.pcap -s 65535 > /dev/null 2>&1 &

# Start C2 server based on protocol
case $C2_PROTOCOL in
    "http")
        echo "[$(date)] Starting HTTP C2 server..."
        python3 /opt/c2/http_c2.py --port $C2_PORT
        ;;
    "https")
        echo "[$(date)] Starting HTTPS C2 server..."
        python3 /opt/c2/https_c2.py --port $C2_PORT
        ;;
    "websocket")
        echo "[$(date)] Starting WebSocket C2 server..."
        python3 /opt/c2/websocket_c2.py --port $C2_PORT
        ;;
    "ssh")
        echo "[$(date)] Starting SSH C2 server..."
        python3 /opt/c2/ssh_c2.py --port $C2_PORT
        ;;
    *)
        echo "[$(date)] Starting default HTTP C2 server..."
        python3 /opt/c2/http_c2.py --port $C2_PORT
        ;;
esac

# Keep container running
echo "[$(date)] C2 server is ready!"
tail -f /dev/null 