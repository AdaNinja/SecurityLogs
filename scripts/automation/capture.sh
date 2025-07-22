#!/bin/bash

# Low-and-Slow SQL Injection Capture Script
# Supports variant configuration via --variant parameter

set -e

# Default values
VARIANT="default"
TIMESTAMP=$(date +"%Y-%m-%dT%H%M")
SCENARIO_NAME="low-and-slow-sqli"
LOG_FILE="../logs/${TIMESTAMP}__${SCENARIO_NAME}.log"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --variant)
            VARIANT="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--variant stealthy|aggressive|moderate|default]"
            echo "  --variant: Attack variant to use (default: default)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Load configuration based on variant
load_config() {
    local variant=$1
    
    # Load base configuration
    if [ -f "../scenarios/low-and-slow-sqli/config/scenario.env" ]; then
        echo "Loading base configuration..."
        export $(cat ../scenarios/low-and-slow-sqli/config/scenario.env | grep -v '^#' | xargs)
    fi
    
    # Load variant-specific configuration
    if [ -f "../scenarios/low-and-slow-sqli/config/variants/${variant}.env" ]; then
        echo "Loading variant configuration: ${variant}"
        export $(cat ../scenarios/low-and-slow-sqli/config/variants/${variant}.env | grep -v '^#' | xargs)
    else
        echo "Warning: Variant configuration not found: ../scenarios/low-and-slow-sqli/config/variants/${variant}.env"
    fi
    
    # Load project-wide configuration
    if [ -f "../.env" ]; then
        echo "Loading project configuration..."
        export $(cat ../.env | grep -v '^#' | xargs)
    fi
}

# Initialize logging
init_logging() {
    mkdir -p ../data/logs
    exec 1> >(tee -a "$LOG_FILE")
    exec 2> >(tee -a "$LOG_FILE" >&2)
    
    echo "=== SQL Injection Capture Started ==="
    echo "Timestamp: $TIMESTAMP"
    echo "Variant: $VARIANT"
    echo "Log file: $LOG_FILE"
    echo "====================================="
}

# Start containers
start_containers() {
    echo "Starting containers..."
    cd ../scenarios/low-and-slow-sqli
    docker-compose up -d
    
    # Wait for containers to be ready
    echo "Waiting for containers to be ready..."
    sleep 30
    
    # Verify container status
    echo "Container status:"
    docker-compose ps
}

# Apply network conditions
apply_network_conditions() {
    if [ "$NETWORK_DELAY" != "0" ] || [ "$PACKET_LOSS" != "0" ]; then
        echo "Applying network conditions..."
        echo "  Delay: ${NETWORK_DELAY}ms"
        echo "  Packet loss: ${PACKET_LOSS}%"
        echo "  Jitter: ${JITTER}ms"
        
        bash ../network/apply_netem.sh \
            --delay "$NETWORK_DELAY" \
            --loss "$PACKET_LOSS" \
            --jitter "$JITTER"
    else
        echo "Skipping network conditions (all set to 0)"
    fi
}

# Start traffic capture
start_capture() {
    echo "Starting traffic capture..."
    
    # Start tcpdump in background
    docker exec securitylogs-tcpdump tcpdump -i eth0 -w "/pcaps/${TIMESTAMP}_${VARIANT}.pcap" &
    TCPDUMP_PID=$!
    
    echo "Traffic capture started (PID: $TCPDUMP_PID)"
}

# Run benign traffic simulation
run_benign_traffic() {
    echo "Starting benign traffic simulation..."
    
    # Run benign traffic in background
    docker exec securitylogs-webapp bash /opt/scripts/benign_modules/run_benign.sh &
    BENIGN_PID=$!
    
    echo "Benign traffic started (PID: $BENIGN_PID)"
    
    # Wait for initial benign traffic
    sleep 60
}

# Run attack
run_attack() {
    echo "Starting attack sequence..."
    
    # Phase 1: Reconnaissance
    echo "Phase 1: Reconnaissance"
    docker exec securitylogs-attacker bash /opt/scripts/run_recon.sh
    
    # Wait between phases
    echo "Waiting ${ATTACK_DELAY} seconds before attack phase..."
    sleep "$ATTACK_DELAY"
    
    # Phase 2: SQL Injection
    echo "Phase 2: SQL Injection"
    docker exec securitylogs-attacker python3 /opt/scripts/attack_modules/container_attack.py
    
    echo "Attack sequence completed"
}

# Stop capture and collect data
stop_capture() {
    echo "Stopping traffic capture..."
    
    # Stop tcpdump
    if [ ! -z "$TCPDUMP_PID" ]; then
        kill $TCPDUMP_PID 2>/dev/null || true
    fi
    
    # Stop benign traffic
    if [ ! -z "$BENIGN_PID" ]; then
        kill $BENIGN_PID 2>/dev/null || true
    fi
    
    # Wait for processes to finish
    sleep 5
    
    echo "Traffic capture stopped"
}

# Collect and organize data
collect_data() {
    echo "Collecting and organizing data..."
    
    # Create output directory
    OUTPUT_DIR="../data/pcap/${SCENARIO_NAME}/${TIMESTAMP}_${VARIANT}"
    mkdir -p "$OUTPUT_DIR"
    
    # Copy pcap file
    if [ -f "../data/pcap/${SCENARIO_NAME}/${TIMESTAMP}_${VARIANT}.pcap" ]; then
        mv "../data/pcap/${SCENARIO_NAME}/${TIMESTAMP}_${VARIANT}.pcap" "$OUTPUT_DIR/"
        echo "PCAP file saved: $OUTPUT_DIR/${TIMESTAMP}_${VARIANT}.pcap"
    fi
    
    # Copy logs
    cp "$LOG_FILE" "$OUTPUT_DIR/"
    
    # Copy container logs
    docker-compose logs > "$OUTPUT_DIR/container_logs.txt"
    
    # Copy attack output
    if [ -d "/opt/output" ]; then
        docker cp securitylogs-attacker:/opt/output "$OUTPUT_DIR/"
    fi
    
    echo "Data collection completed: $OUTPUT_DIR"
}

# Cleanup
cleanup() {
    echo "Cleaning up..."
    
    # Stop containers
    cd ../scenarios/low-and-slow-sqli
    docker-compose down
    
    # Reset network conditions
    bash ../network/reset_netem.sh
    
    echo "Cleanup completed"
}

# Main execution
main() {
    echo "Starting SQL injection capture with variant: $VARIANT"
    
    # Load configuration
    load_config "$VARIANT"
    
    # Initialize logging
    init_logging
    
    # Execute capture sequence
    start_containers
    apply_network_conditions
    start_capture
    run_benign_traffic
    run_attack
    
    # Wait for attack to complete
    echo "Waiting for attack to complete..."
    sleep "$INJECTION_DURATION"
    
    # Collect data
    stop_capture
    collect_data
    cleanup
    
    echo "=== SQL Injection Capture Completed ==="
    echo "Results saved to: ../data/pcap/${SCENARIO_NAME}/${TIMESTAMP}_${VARIANT}/"
}

# Handle script interruption
trap 'echo "Script interrupted. Cleaning up..."; cleanup; exit 1' INT TERM

# Run main function
main "$@"
