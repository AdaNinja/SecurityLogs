#!/bin/bash

# Network Traffic Capture Script
# Captures all network traffic during attack scenarios

set -e

echo "[$(date)] Starting Network Traffic Capture..."

# Create capture directory
mkdir -p /pcaps

# Set capture parameters
INTERFACE=${CAPTURE_INTERFACE:-"eth0"}
FILTER=${CAPTURE_FILTER:-""}
CAPTURE_FILE="/pcaps/traffic_$(date +%Y%m%d_%H%M%S).pcap"

echo "[$(date)] Capture Configuration:"
echo "  Interface: $INTERFACE"
echo "  Filter: $FILTER"
echo "  Output: $CAPTURE_FILE"

# Start tcpdump with appropriate filters
if [ -n "$FILTER" ]; then
    echo "[$(date)] Starting tcpdump with filter: $FILTER"
    tcpdump -i "$INTERFACE" -w "$CAPTURE_FILE" -s 65535 "$FILTER"
else
    echo "[$(date)] Starting tcpdump without filter"
    tcpdump -i "$INTERFACE" -w "$CAPTURE_FILE" -s 65535
fi

# Keep script running
echo "[$(date)] Traffic capture started..."
tail -f /dev/null 