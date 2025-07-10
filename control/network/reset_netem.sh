#!/bin/bash

# Network Condition Reset Script
# Removes all netem and traffic control rules from containers

set -e

# Function to reset netem for a container
reset_netem_for_container() {
    local container_name=$1
    
    echo "Resetting netem for container: $container_name"
    
    # Get container PID
    local pid=$(docker inspect -f '{{.State.Pid}}' "$container_name" 2>/dev/null)
    if [ -z "$pid" ]; then
        echo "Warning: Container $container_name not found or not running"
        return 1
    fi
    
    # Get interface name
    local iface=$(docker exec "$container_name" cat /proc/net/dev | grep eth0 | awk -F: '{print $1}' | tr -d ' ')
    if [ -z "$iface" ]; then
        echo "Warning: Interface eth0 not found in container $container_name"
        return 1
    fi
    
    echo "  Container: $container_name (PID: $pid, Interface: $iface)"
    
    # Remove all qdisc rules
    echo "  Removing all traffic control rules..."
    nsenter -t "$pid" -n tc qdisc del dev "$iface" root 2>/dev/null || true
    nsenter -t "$pid" -n tc qdisc del dev "$iface" ingress 2>/dev/null || true
    
    echo "  Netem reset successfully for $container_name"
}

# Main execution
main() {
    echo "=== Resetting Network Conditions ==="
    
    # List of containers to reset netem for
    containers=("securitylogs-webapp" "securitylogs-attacker")
    
    for container in "${containers[@]}"; do
        if docker ps --format "table {{.Names}}" | grep -q "$container"; then
            reset_netem_for_container "$container"
        else
            echo "Container $container is not running, skipping..."
        fi
    done
    
    echo "=== Network Conditions Reset ==="
}

# Check if running as root (required for netem)
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (sudo required for netem)"
    exit 1
fi

# Run main function
main "$@"
