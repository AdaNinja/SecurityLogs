#!/bin/bash

# Interleaved Attack and Benign Traffic Script
# Runs attack and benign traffic simultaneously to mimic real-world conditions

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="../../data"
OUTPUT_DIR="$DATA_DIR/output"
LOGS_DIR="$DATA_DIR/logs"
PCAP_DIR="$DATA_DIR/pcap"

# Default configuration
ATTACK_VARIANTS=("stealthy" "moderate" "aggressive")
BENIGN_PROTOCOL_MIX="HTTP:0.6,DNS:0.3,SMTP:0.1"
BENIGN_DURATION=300
ATTACK_DELAY_MIN=5
ATTACK_DELAY_MAX=15
BENIGN_WARMUP_TIME=15

# Function to log messages
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --attack-variants LIST    Attack variants to run (default: stealthy,moderate,aggressive)"
    echo "  --benign-mix MIX         Benign traffic protocol mix (default: HTTP:0.6,DNS:0.3,SMTP:0.1)"
    echo "  --benign-duration SEC    Benign traffic duration in seconds (default: 300)"
    echo "  --attack-delay MIN-MAX   Attack delay range in seconds (default: 5-15)"
    echo "  --warmup-time SEC        Benign traffic warmup time (default: 15)"
    echo "  --help                   Show this help message"
    echo ""
    echo "Attack Variants:"
    echo "  stealthy    - RISK=1, LEVEL=1 (low and slow)"
    echo "  moderate    - RISK=1, LEVEL=2 (balanced)"
    echo "  aggressive  - RISK=2, LEVEL=3 (high intensity)"
    echo ""
    echo "Examples:"
    echo "  $0 --attack-variants stealthy,aggressive"
    echo "  $0 --benign-mix HTTP:0.8,DNS:0.2 --attack-delay 10-20"
    echo "  $0 --attack-variants stealthy --benign-duration 600"
}

# Function to parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --attack-variants)
                IFS=',' read -ra ATTACK_VARIANTS <<< "$2"
                shift 2
                ;;
            --benign-mix)
                BENIGN_PROTOCOL_MIX="$2"
                shift 2
                ;;
            --benign-duration)
                BENIGN_DURATION="$2"
                shift 2
                ;;
            --attack-delay)
                IFS='-' read -r ATTACK_DELAY_MIN ATTACK_DELAY_MAX <<< "$2"
                shift 2
                ;;
            --warmup-time)
                BENIGN_WARMUP_TIME="$2"
                shift 2
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Function to check if containers are running
check_containers() {
    log "Checking container status..."
    
    containers=("securitylogs-webapp" "securitylogs-tcpdump" "securitylogs-attacker")
    
    for container in "${containers[@]}"; do
        if docker ps --format "table {{.Names}}" | grep -q "$container"; then
            log "✓ $container is running"
        else
            error "$container is not running"
            return 1
        fi
    done
    
    log "All containers are running"
    return 0
}

# Function to wait for webapp to be ready
wait_for_webapp() {
    log "Waiting for webapp to be ready..."
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f -s http://localhost:8080/ > /dev/null 2>&1; then
            log "✓ Webapp is ready"
            return 0
        fi
        
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    error "Webapp did not become ready in time"
    return 1
}

# Function to start benign traffic
start_benign_traffic() {
    log "Starting benign traffic simulation..."
    log "Protocol mix: $BENIGN_PROTOCOL_MIX"
    log "Duration: $BENIGN_DURATION seconds"
    
    # Use existing benign traffic script with custom configuration
    docker exec securitylogs-webapp bash /opt/scripts/benign_modules/run_benign.sh \
        --protocol-mix "$BENIGN_PROTOCOL_MIX" \
        --duration "$BENIGN_DURATION" &
    local benign_pid=$!
    log "✓ Benign traffic started (PID: $benign_pid)"
    
    # Store PID for later cleanup
    echo "$benign_pid" > /tmp/benign_pids.txt
    
    log "✓ Benign traffic simulation started"
}

# Function to stop benign traffic
stop_benign_traffic() {
    log "Stopping benign traffic..."
    
    if [ -f /tmp/benign_pids.txt ]; then
        local pids=$(cat /tmp/benign_pids.txt)
        for pid in $pids; do
            if kill -0 $pid 2>/dev/null; then
                kill $pid
                log "✓ Stopped process $pid"
            fi
        done
        rm -f /tmp/benign_pids.txt
    fi
    
    # Also stop any remaining benign traffic processes in webapp container
    docker exec securitylogs-webapp pkill -f "run_benign.sh" 2>/dev/null || true
    docker exec securitylogs-webapp pkill -f "http_traffic.sh" 2>/dev/null || true
    docker exec securitylogs-webapp pkill -f "dns_traffic.sh" 2>/dev/null || true
    docker exec securitylogs-webapp pkill -f "smtp_traffic.sh" 2>/dev/null || true
    
    log "✓ All benign traffic stopped"
}

# Function to run attack variant
run_attack_variant() {
    local variant="$1"
    local risk level
    
    case "$variant" in
        "stealthy")
            risk=1
            level=1
            ;;
        "moderate")
            risk=1
            level=2
            ;;
        "aggressive")
            risk=2
            level=3
            ;;
        *)
            error "Unknown attack variant: $variant"
            return 1
            ;;
    esac
    
    log "Running $variant attack variant (RISK=$risk, LEVEL=$level)..."
    
    # Run the attack with specific parameters
    if docker exec securitylogs-attacker python3 /opt/scripts/container_attack.py \
        --risk "$risk" --level "$level" --variant "$variant"; then
        log "✓ $variant attack completed successfully"
        return 0
    else
        error "$variant attack failed"
        return 1
    fi
}

# Function to run interleaved attack
run_interleaved_attack() {
    log "Starting interleaved attack simulation..."
    log "Attack variants: ${ATTACK_VARIANTS[*]}"
    log "Benign warmup time: $BENIGN_WARMUP_TIME seconds"
    log "Attack delay range: $ATTACK_DELAY_MIN-$ATTACK_DELAY_MAX seconds"
    
    # Create timestamp for this run
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local run_dir="$OUTPUT_DIR/interleaved_run_$timestamp"
    
    mkdir -p "$run_dir"
    
    # Start benign traffic first
    start_benign_traffic
    
    # Wait for benign traffic to establish
    log "Waiting for benign traffic to establish ($BENIGN_WARMUP_TIME seconds)..."
    sleep "$BENIGN_WARMUP_TIME"
    
    # Run attack variants with delays
    local successful_variants=0
    local total_variants=${#ATTACK_VARIANTS[@]}
    
    for variant in "${ATTACK_VARIANTS[@]}"; do
        log "Running $variant attack variant (interleaved with benign traffic)..."
        
        # Run the attack
        if run_attack_variant "$variant"; then
            successful_variants=$((successful_variants + 1))
        fi
        
        # Random delay between attacks
        if [ $successful_variants -lt $total_variants ]; then
            local delay=$((ATTACK_DELAY_MIN + RANDOM % (ATTACK_DELAY_MAX - ATTACK_DELAY_MIN + 1)))
            log "Waiting $delay seconds before next variant..."
            sleep $delay
        fi
    done
    
    # Stop benign traffic
    stop_benign_traffic
    
    log "Interleaved attack completed: $successful_variants/$total_variants variants successful"
    
    # Collect data
    collect_data "$run_dir"
    
    return $((total_variants - successful_variants))
}

# Function to collect data
collect_data() {
    local run_dir="$1"
    log "Collecting interleaved experiment data..."
    
    # Collect container logs
    for container in "securitylogs-webapp" "securitylogs-tcpdump" "securitylogs-attacker" "securitylogs-log-aggregator"; do
        log "Collecting logs from $container..."
        docker logs "$container" > "$run_dir/${container}_logs.txt" 2>&1 || true
    done
    
    # Collect PCAP files
    if [ -f "$PCAP_DIR/traffic.pcap" ]; then
        cp "$PCAP_DIR/traffic.pcap" "$run_dir/"
        log "✓ Copied traffic.pcap"
    fi
    
    if [ -f "$PCAP_DIR/webapp_traffic.pcap" ]; then
        cp "$PCAP_DIR/webapp_traffic.pcap" "$run_dir/"
        log "✓ Copied webapp_traffic.pcap"
    fi
    
    # Collect attack results
    if [ -d "$OUTPUT_DIR/variants" ]; then
        cp -r "$OUTPUT_DIR/variants" "$run_dir/"
        log "✓ Copied attack results"
    fi
    
    # Generate summary report
    log "Generating interleaved experiment summary..."
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    
    cat > "$run_dir/interleaved_summary.md" << EOF
# SecurityLogs Interleaved Experiment Summary

**Experiment Timestamp:** $timestamp  
**Run Directory:** $run_dir

## Experiment Configuration

- **Attack Variants:** ${ATTACK_VARIANTS[*]}
- **Benign Protocol Mix:** $BENIGN_PROTOCOL_MIX
- **Benign Duration:** $BENIGN_DURATION seconds
- **Attack Delay Range:** $ATTACK_DELAY_MIN-$ATTACK_DELAY_MAX seconds
- **Benign Warmup Time:** $BENIGN_WARMUP_TIME seconds

## Experiment Details

- **Scenario:** Low-and-Slow SQL Injection Attack (Interleaved)
- **Data Collection:** Complete logs and PCAP files

## Interleaved Execution

This experiment runs attack and benign traffic simultaneously to mimic real-world conditions where malicious traffic is hidden among normal network activity.

### Benign Traffic Types
- HTTP traffic simulation
- DNS query simulation  
- SMTP session simulation

### Attack Variants
EOF
    
    for variant in "${ATTACK_VARIANTS[@]}"; do
        case "$variant" in
            "stealthy")
                echo "- Stealthy (RISK=1, LEVEL=1)" >> "$run_dir/interleaved_summary.md"
                ;;
            "moderate")
                echo "- Moderate (RISK=1, LEVEL=2)" >> "$run_dir/interleaved_summary.md"
                ;;
            "aggressive")
                echo "- Aggressive (RISK=2, LEVEL=3)" >> "$run_dir/interleaved_summary.md"
                ;;
        esac
    done
    
    cat >> "$run_dir/interleaved_summary.md" << EOF

## Files Collected

### Container Logs
- securitylogs-webapp_logs.txt
- securitylogs-tcpdump_logs.txt
- securitylogs-attacker_logs.txt
- securitylogs-log-aggregator_logs.txt

### Network Traffic
EOF
    
    if [ -f "$run_dir/traffic.pcap" ]; then
        echo "- traffic.pcap" >> "$run_dir/interleaved_summary.md"
    fi
    
    if [ -f "$run_dir/webapp_traffic.pcap" ]; then
        echo "- webapp_traffic.pcap" >> "$run_dir/interleaved_summary.md"
    fi
    
    cat >> "$run_dir/interleaved_summary.md" << EOF

### Attack Results
- variants/ (if available)

## Analysis Commands

\`\`\`bash
# Analyze PCAP files for interleaved traffic
tcpdump -r $run_dir/traffic.pcap -c 50

# View container logs
less $run_dir/securitylogs-webapp_logs.txt

# Run multi-source logger
python3 ../../control/multi_source_logger.py
\`\`\`

## Interleaved Traffic Analysis

The collected data contains both benign and malicious traffic interleaved, making it more realistic for security research and detection system testing.

EOF
    
    log "✓ Interleaved summary report generated: $run_dir/interleaved_summary.md"
    log "✓ All data collected in: $run_dir"
}

# Function to cleanup on exit
cleanup() {
    log "Cleaning up..."
    stop_benign_traffic
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Main execution
main() {
    echo -e "${BLUE}SecurityLogs Interleaved Attack and Benign Traffic${NC}"
    echo "========================================================"
    echo ""
    
    # Parse command line arguments
    parse_args "$@"
    
    # Check if we're in the right directory
    if [ ! -f "docker-compose.yml" ]; then
        error "docker-compose.yml not found. Please run this script from the scenario directory."
        exit 1
    fi
    
    # Check if containers are running
    if ! check_containers; then
        log "Starting containers..."
        docker-compose up -d
        sleep 10
        
        if ! check_containers; then
            error "Failed to start containers"
            exit 1
        fi
    fi
    
    # Wait for webapp to be ready
    if ! wait_for_webapp; then
        error "Webapp is not responding"
        exit 1
    fi
    
    # Run interleaved attack
    if ! run_interleaved_attack; then
        warn "Some attack variants failed, but continuing with data collection"
    fi
    
    # Final summary
    echo ""
    echo -e "${BLUE}Interleaved Experiment Complete${NC}"
    echo "====================================="
    echo "✓ Benign traffic started and stopped"
    echo "✓ Attack variants executed"
    echo "✓ Data collected and report generated"
    echo ""
    echo "Check the experiment results in the output directory."
}

# Run main function
main "$@" 