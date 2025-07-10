#!/bin/bash

# Network Condition Application Script
# Applies delay, loss, and jitter to container network interfaces

set -e

# Default values
DELAY=100
LOSS=1
JITTER=20
BANDWIDTH=10

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --delay)
            DELAY="$2"
            shift 2
            ;;
        --loss)
            LOSS="$2"
            shift 2
            ;;
        --jitter)
            JITTER="$2"
            shift 2
            ;;
        --bandwidth)
            BANDWIDTH="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--delay MS] [--loss PERCENT] [--jitter MS] [--bandwidth MBPS]"
            echo "  --delay: Network delay in milliseconds (default: 100)"
            echo "  --loss: Packet loss percentage (default: 1)"
            echo "  --jitter: Network jitter in milliseconds (default: 20)"
            echo "  --bandwidth: Bandwidth limit in Mbps (default: 10)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Function to apply netem to a container
apply_netem_to_container() {
    local container_name=$1
    local interface="eth0"
    
    echo "Applying netem to container: $container_name"
    
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
    
    # Apply netem rules
    echo "  Container: $container_name (PID: $pid, Interface: $iface)"
    echo "  Delay: ${DELAY}ms, Loss: ${LOSS}%, Jitter: ${JITTER}ms"
    
    # Remove existing qdisc if present
    nsenter -t "$pid" -n tc qdisc del dev "$iface" root 2>/dev/null || true
    
    # Apply new qdisc with netem
    if [ "$DELAY" != "0" ] || [ "$LOSS" != "0" ] || [ "$JITTER" != "0" ]; then
        local netem_cmd="tc qdisc add dev $iface root netem"
        
        if [ "$DELAY" != "0" ]; then
            netem_cmd="$netem_cmd delay ${DELAY}ms"
        fi
        
        if [ "$JITTER" != "0" ]; then
            netem_cmd="$netem_cmd ${JITTER}ms"
        fi
        
        if [ "$LOSS" != "0" ]; then
            netem_cmd="$netem_cmd loss ${LOSS}%"
        fi
        
        echo "  Executing: $netem_cmd"
        nsenter -t "$pid" -n $netem_cmd
        
        echo "  Netem applied successfully to $container_name"
    else
        echo "  Skipping netem (all values are 0)"
    fi
}

# Function to apply bandwidth limit
apply_bandwidth_limit() {
    local container_name=$1
    local interface="eth0"
    
    if [ "$BANDWIDTH" != "0" ]; then
        echo "Applying bandwidth limit to container: $container_name"
        
        local pid=$(docker inspect -f '{{.State.Pid}}' "$container_name" 2>/dev/null)
        if [ -z "$pid" ]; then
            echo "Warning: Container $container_name not found or not running"
            return 1
        fi
        
        local iface=$(docker exec "$container_name" cat /proc/net/dev | grep eth0 | awk -F: '{print $1}' | tr -d ' ')
        if [ -z "$iface" ]; then
            echo "Warning: Interface eth0 not found in container $container_name"
            return 1
        fi
        
        # Add bandwidth limit using tbf (token bucket filter)
        echo "  Bandwidth limit: ${BANDWIDTH}Mbps"
        nsenter -t "$pid" -n tc qdisc add dev "$iface" parent 1:1 handle 10: tbf rate "${BANDWIDTH}mbit" burst 32kbit latency 400ms
        
        echo "  Bandwidth limit applied successfully to $container_name"
    fi
}

# Main execution
main() {
    echo "=== Applying Network Conditions ==="
    echo "Delay: ${DELAY}ms"
    echo "Loss: ${LOSS}%"
    echo "Jitter: ${JITTER}ms"
    echo "Bandwidth: ${BANDWIDTH}Mbps"
    echo "=================================="
    
    # List of containers to apply netem to
    containers=("securitylogs-webapp" "securitylogs-attacker")
    
    for container in "${containers[@]}"; do
        if docker ps --format "table {{.Names}}" | grep -q "$container"; then
            apply_netem_to_container "$container"
            apply_bandwidth_limit "$container"
        else
            echo "Container $container is not running, skipping..."
        fi
    done
    
    echo "=== Network Conditions Applied ==="
}

# Check if running as root (required for netem)
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (sudo required for netem)"
    exit 1
fi

# Run main function
main "$@"
