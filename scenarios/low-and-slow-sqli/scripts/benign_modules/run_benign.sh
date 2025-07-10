#!/bin/bash

# Benign Traffic Generation Script
# Generates realistic background traffic for attack scenarios

set -e

# Load configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load YAML configuration if available
if [ -f "$SCRIPT_DIR/../config_loader.py" ]; then
    # Use Python config loader to get protocol mix
    PROTOCOL_MIX=$(python3 "$SCRIPT_DIR/../config_loader.py" --variant "${VARIANT:-moderate}" 2>/dev/null | grep -o 'PROTOCOL_MIX=[^[:space:]]*' | cut -d'=' -f2)
fi

# Default values (fallback)
PROTOCOL_MIX=${PROTOCOL_MIX:-"HTTP:0.7,DNS:0.2,SMTP:0.1"}
TOTAL_DURATION=${BENIGN_TOTAL_DURATION:-2400}
LOG_FILE="/tmp/benign_traffic.log"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --protocol-mix)
            PROTOCOL_MIX="$2"
            shift 2
            ;;
        --duration)
            TOTAL_DURATION="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --protocol-mix MIX    Protocol mix (e.g., HTTP:0.7,DNS:0.2,SMTP:0.1)"
            echo "  --duration SECONDS    Total duration in seconds"
            echo "  --help               Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] BENIGN: $1" | tee -a "$LOG_FILE"
}

parse_protocol_mix() {
    local mix="$1"
    local -A protocols
    
    IFS=',' read -ra PROTOCOLS <<< "$mix"
    for protocol in "${PROTOCOLS[@]}"; do
        IFS=':' read -ra PARTS <<< "$protocol"
        if [ ${#PARTS[@]} -eq 2 ]; then
            protocols["${PARTS[0]}"]="${PARTS[1]}"
        fi
    done
    
    echo "${protocols[@]}"
}

start_protocol_traffic() {
    local protocol="$1"
    local ratio="$2"
    local duration="$3"
    
    log_message "Starting $protocol traffic (ratio: $ratio, duration: $duration seconds)"
    
    case $protocol in
        "HTTP")
                bash "$SCRIPT_DIR/http_traffic.sh" &
            HTTP_PID=$!
            ;;
        "DNS")
                bash "$SCRIPT_DIR/dns_traffic.sh" &
            DNS_PID=$!
            ;;
        "SMTP")
                bash "$SCRIPT_DIR/smtp_traffic.sh" &
            SMTP_PID=$!
            ;;
        *)
            log_message "Unknown protocol: $protocol"
            return 1
            ;;
    esac
    
    log_message "$protocol traffic started with PID: $!"
}

main() {
    log_message "Starting benign traffic generation"
    log_message "Protocol mix: $PROTOCOL_MIX"
    log_message "Total duration: $TOTAL_DURATION seconds"
    
    # Parse protocol mix
    local -A protocols
    IFS=',' read -ra PROTOCOLS <<< "$PROTOCOL_MIX"
    for protocol in "${PROTOCOLS[@]}"; do
        IFS=':' read -ra PARTS <<< "$protocol"
        if [ ${#PARTS[@]} -eq 2 ]; then
            protocols["${PARTS[0]}"]="${PARTS[1]}"
        fi
    done
    
    # Start traffic for each protocol
    local pids=()
    for protocol in "${!protocols[@]}"; do
        ratio="${protocols[$protocol]}"
        # Calculate duration based on ratio
        duration=$(echo "$TOTAL_DURATION * $ratio" | bc -l | cut -d. -f1)
        
        start_protocol_traffic "$protocol" "$ratio" "$duration"
        pids+=($!)
        
        # Small delay between starting different protocols
        sleep 2
    done
    
    log_message "All benign traffic modules started"
    log_message "Waiting for completion..."
    
    # Wait for all background processes
    for pid in "${pids[@]}"; do
        wait $pid
    done
    
    log_message "Benign traffic generation completed"
}

# Cleanup function
cleanup() {
    log_message "Cleaning up benign traffic processes..."
    # Kill all background processes
    jobs -p | xargs -r kill
    log_message "Cleanup completed"
}

# Set up signal handlers
trap cleanup EXIT INT TERM

# Main execution
main "$@"
