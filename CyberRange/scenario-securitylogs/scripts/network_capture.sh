#!/bin/bash
# Network capture script for Docker bridge networks
# This script runs on the host machine to capture traffic from Docker bridge networks

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$(dirname "$SCRIPT_DIR")"
# Use MODE environment variable to determine output directory, default to network
MODE="${MODE:-network}"
OUTPUT_DIR="$SCENARIO_DIR/out/${MODE}/pcap"
BRIDGE_NAME="br-edge"  # Docker bridge network name
CAPTURE_FILE=""
TCPDUMP_PID=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -s, --start [EXPERIMENT_NAME]    Start network capture"
    echo "  -t, --stop                       Stop network capture"
    echo "  -r, --restart [EXPERIMENT_NAME]  Restart network capture"
    echo "  -l, --list                       List capture files"
    echo "  -c, --clean                      Clean old capture files"
    echo "  -h, --help                       Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 --start attack1              # Start capture for attack1"
    echo "  $0 --stop                       # Stop current capture"
    echo "  $0 --restart attack2            # Restart capture for attack2"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
        exit 1
    fi
}

# Function to find Docker bridge network
find_bridge() {
    local bridge_name="$1"
    
    # Try to find the bridge by name
    if ip link show "$bridge_name" >/dev/null 2>&1; then
        echo "$bridge_name"
        return 0
    fi
    
    # Try to find bridge by Docker network name
    local docker_network="ras-vanilla-edge"
    if ip link show "$docker_network" >/dev/null 2>&1; then
        echo "$docker_network"
        return 0
    fi
    
    # Try to find the edge network bridge dynamically
    local edge_bridge=""
    if docker network ls | grep -q "ras-vanilla-edge"; then
        local network_id=$(docker network ls | grep "ras-vanilla-edge" | awk '{print $1}')
        edge_bridge="br-$network_id"
        if ip link show "$edge_bridge" >/dev/null 2>&1; then
            echo "$edge_bridge"
            return 0
        fi
    fi
    
    # List available bridges
    echo -e "${YELLOW}Available bridge networks:${NC}"
    ip link show | grep -E "^[0-9]+: br-" | awk '{print $2}' | sed 's/://'
    
    echo -e "${RED}Error: Bridge network '$bridge_name' not found${NC}"
    return 1
}

# Function to start capture
start_capture() {
    local experiment_name="$1"
    
    if [[ -z "$experiment_name" ]]; then
        echo -e "${RED}Error: Experiment name is required${NC}"
        exit 1
    fi
    
    check_root
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Find bridge network
    local bridge=$(find_bridge "$BRIDGE_NAME")
    if [[ $? -ne 0 ]]; then
        exit 1
    fi
    
    # Generate capture file name with timestamp
    local timestamp=$(date +%Y%m%d_%H%M%S)
    CAPTURE_FILE="$OUTPUT_DIR/${experiment_name}_${timestamp}.pcap"
    
    echo -e "${BLUE}Starting network capture...${NC}"
    echo -e "${GREEN}Bridge: $bridge${NC}"
    echo -e "${GREEN}Output: $CAPTURE_FILE${NC}"
    echo -e "${GREEN}Experiment: $experiment_name${NC}"
    
    # Start tcpdump
    tcpdump -i "$bridge" \
        -w "$CAPTURE_FILE" \
        -s 0 \
        -n \
        'tcp or udp' \
        &
    
    TCPDUMP_PID=$!
    
    # Save metadata
    cat > "$OUTPUT_DIR/${experiment_name}_${timestamp}.meta" << EOF
EXPERIMENT_NAME=$experiment_name
START_TIME=$(date -Iseconds)
BRIDGE_NETWORK=$bridge
CAPTURE_FILE=$(basename "$CAPTURE_FILE")
TCPDUMP_PID=$TCPDUMP_PID
EOF
    
    # Save PID for later use
    echo "$TCPDUMP_PID" > "$OUTPUT_DIR/tcpdump.pid"
    echo "$CAPTURE_FILE" > "$OUTPUT_DIR/current_capture.txt"
    
    echo -e "${GREEN}Network capture started with PID: $TCPDUMP_PID${NC}"
    echo -e "${YELLOW}To stop capture, run: $0 --stop${NC}"
}

# Function to stop capture
stop_capture() {
    check_root
    
    local pid_file="$OUTPUT_DIR/tcpdump.pid"
    local capture_file="$OUTPUT_DIR/current_capture.txt"
    
    if [[ ! -f "$pid_file" ]]; then
        echo -e "${YELLOW}No active capture found${NC}"
        return 0
    fi
    
    local pid=$(cat "$pid_file")
    
    if kill -0 "$pid" 2>/dev/null; then
        echo -e "${BLUE}Stopping network capture (PID: $pid)...${NC}"
        kill "$pid"
        
        # Wait for tcpdump to finish
        sleep 2
        
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "${YELLOW}Force killing tcpdump...${NC}"
            kill -9 "$pid"
        fi
        
        echo -e "${GREEN}Network capture stopped${NC}"
        
        # Update metadata
        if [[ -f "$capture_file" ]]; then
            local cap_file=$(cat "$capture_file")
            local meta_file="${cap_file%.pcap}.meta"
            if [[ -f "$meta_file" ]]; then
                echo "STOP_TIME=$(date -Iseconds)" >> "$meta_file"
                echo "DURATION=$(($(date +%s) - $(date -d "$(grep START_TIME "$meta_file" | cut -d= -f2)" +%s)))s" >> "$meta_file"
            fi
        fi
        
        # Clean up PID files
        rm -f "$pid_file" "$capture_file"
    else
        echo -e "${YELLOW}Process $pid not running${NC}"
        rm -f "$pid_file" "$capture_file"
    fi
}

# Function to restart capture
restart_capture() {
    local experiment_name="$1"
    
    echo -e "${BLUE}Restarting network capture...${NC}"
    stop_capture
    sleep 1
    start_capture "$experiment_name"
}

# Function to list capture files
list_captures() {
    echo -e "${BLUE}Network capture files:${NC}"
    if [[ -d "$OUTPUT_DIR" ]]; then
        ls -la "$OUTPUT_DIR"/*.pcap 2>/dev/null || echo -e "${YELLOW}No capture files found${NC}"
        
        echo -e "\n${BLUE}Metadata files:${NC}"
        ls -la "$OUTPUT_DIR"/*.meta 2>/dev/null || echo -e "${YELLOW}No metadata files found${NC}"
    else
        echo -e "${YELLOW}Output directory not found: $OUTPUT_DIR${NC}"
    fi
}

# Function to clean old captures
clean_captures() {
    echo -e "${YELLOW}Cleaning old capture files...${NC}"
    if [[ -d "$OUTPUT_DIR" ]]; then
        rm -f "$OUTPUT_DIR"/*.pcap
        rm -f "$OUTPUT_DIR"/*.meta
        rm -f "$OUTPUT_DIR"/tcpdump.pid
        rm -f "$OUTPUT_DIR"/current_capture.txt
        echo -e "${GREEN}Old capture files cleaned${NC}"
    else
        echo -e "${YELLOW}Output directory not found: $OUTPUT_DIR${NC}"
    fi
}

# Main script logic
case "${1:-}" in
    -s|--start)
        start_capture "$2"
        ;;
    -t|--stop)
        stop_capture
        ;;
    -r|--restart)
        restart_capture "$2"
        ;;
    -l|--list)
        list_captures
        ;;
    -c|--clean)
        clean_captures
        ;;
    -h|--help|*)
        show_usage
        ;;
esac 