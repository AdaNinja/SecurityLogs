#!/bin/bash

# Single Variant Experiment Script
# Runs one attack variant in complete isolation to avoid data contamination

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$SCENARIO_DIR/config"

# Load environment variables
if [ -f "$CONFIG_DIR/scenario.env" ]; then
    source "$CONFIG_DIR/scenario.env"
else
    echo "Error: scenario.env not found in $CONFIG_DIR"
    exit 1
fi

# Default values
SCENARIO_NAME=${SCENARIO_NAME:-"low-and-slow-sqli"}
VARIANT_NAME=${VARIANT_NAME:-"moderate"}
TIMESTAMP=${TIMESTAMP:-$(date +%Y%m%d_%H%M%S)}
EXPERIMENT_DIR="../../data/output/single_variant/${VARIANT_NAME}_${TIMESTAMP}"
PCAP_DIR="../../data/pcap"

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
    echo "Usage: $0 [OPTIONS] <variant_name>"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -t, --timestamp TIMESTAMP  Use custom timestamp (default: auto-generated)"
    echo "  -d, --duration SEC      Attack duration in seconds (default: 300)"
    echo "  -b, --benign-duration SEC  Benign traffic duration (default: 600)"
    echo "  -w, --warmup SEC        Warmup time for benign traffic (default: 30)"
    echo ""
    echo "Available variants:"
    echo "  stealthy, moderate, aggressive"
    echo ""
    echo "Examples:"
    echo "  $0 stealthy                    # Run stealthy variant"
    echo "  $0 -t 20240601_143022 moderate # Run moderate with custom timestamp"
    echo "  $0 -d 600 aggressive           # Run aggressive for 10 minutes"
}

# Function to parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -t|--timestamp)
                TIMESTAMP="$2"
                shift 2
                ;;
            -d|--duration)
                ATTACK_DURATION="$2"
                shift 2
                ;;
            -b|--benign-duration)
                BENIGN_DURATION="$2"
                shift 2
                ;;
            -w|--warmup)
                WARMUP_TIME="$2"
                shift 2
                ;;
            *)
                VARIANT_NAME="$1"
                shift
                ;;
        esac
    done
}

# Function to check containers
check_containers() {
    log "Checking container status..."
    
    containers=("securitylogs-webapp" "securitylogs-attacker")
    
    for container in "${containers[@]}"; do
        if docker ps --format "table {{.Names}}" | grep -q "$container"; then
            log "✓ $container is running"
        else
            error "$container is not running"
            return 1
        fi
    done
    
    log "All required containers are running"
    return 0
}

# Function to wait for webapp
wait_for_webapp() {
    log "Waiting for webapp to be ready..."
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if timeout 10 curl -f -s http://localhost:8080/ > /dev/null 2>&1; then
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

# Function to start isolated tcpdump
start_isolated_tcpdump() {
    local variant=$1
    local timestamp=$2
    local pcap_filename="low-and-slow-sqli_${variant}_${timestamp}.pcap"
    
    log "Starting isolated tcpdump for $variant variant..."
    log "PCAP filename: $pcap_filename"
    
    # Create unique container name
    local container_name="tcpdump-${variant}-${timestamp}-isolated"
    
    # Start tcpdump container with isolated network access
    docker run -d \
        --name "$container_name" \
        --network container:securitylogs-webapp \
        -v "$(pwd)/$PCAP_DIR:/pcaps" \
        -v "$(pwd)/$LOGS_DIR:/logs" \
        --cap-add=NET_ADMIN \
        --cap-add=NET_RAW \
        --cap-add=SYS_ADMIN \
        --privileged \
        low-and-slow-sqli-tcpdump:latest \
        /bin/bash -c "tcpdump -i any -w \"/pcaps/$pcap_filename\" -s 65535 -v"
    
    log "✓ Isolated tcpdump started: $container_name"
    echo "$container_name"
}

# Function to stop isolated tcpdump
stop_isolated_tcpdump() {
    local container_name="$1"
    
    log "Stopping isolated tcpdump: $container_name"
    docker stop "$container_name" 2>/dev/null || true
    docker rm "$container_name" 2>/dev/null || true
    log "✓ Isolated tcpdump stopped and removed: $container_name"
}

# Function to run attack variant
run_attack_variant() {
    local variant="$1"
    local duration="$2"
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
    log "Duration: $duration seconds"
    
    # Run the attack with specific parameters
    if docker exec securitylogs-attacker python3 /opt/scripts/container_attack.py \
        --risk "$risk" --level "$level" --variant "$variant" --duration "$duration"; then
        log "✓ $variant attack completed successfully"
        return 0
    else
        error "$variant attack failed"
        return 1
    fi
}

# Function to start benign traffic
start_benign_traffic() {
    local duration="$1"
    
    log "Starting benign traffic simulation..."
    log "Duration: $duration seconds"
    
    # Start benign traffic in background with timeout
    timeout "$duration" docker exec securitylogs-webapp bash /opt/scripts/benign_modules/run_benign.sh \
        --protocol-mix "HTTP:0.7,DNS:0.2,SMTP:0.1" \
        --duration "$duration" &
    
    local benign_pid=$!
    log "✓ Benign traffic started (PID: $benign_pid)"
    echo "$benign_pid"
}

# Function to stop benign traffic
stop_benign_traffic() {
    log "Stopping benign traffic..."
    
    # Stop benign traffic processes
    docker exec securitylogs-webapp pkill -f "run_benign.sh" 2>/dev/null || true
    docker exec securitylogs-webapp pkill -f "http_traffic.sh" 2>/dev/null || true
    docker exec securitylogs-webapp pkill -f "dns_traffic.sh" 2>/dev/null || true
    docker exec securitylogs-webapp pkill -f "smtp_traffic.sh" 2>/dev/null || true
    
    log "✓ All benign traffic stopped"
}

# Function to collect data
collect_data() {
    local experiment_dir="$1"
    local variant="$2"
    local timestamp="$3"
    
    log "Collecting experiment data..."
    
    # Create experiment directory
    sudo mkdir -p "$experiment_dir"
    sudo chown -R $USER:$USER "$experiment_dir"
    
    # Collect attack-specific logs (most important)
    log "Collecting attack-specific logs..."
    if docker exec securitylogs-attacker test -f /opt/output/container_attack_log.json; then
        docker exec securitylogs-attacker cat /opt/output/container_attack_log.json > "$experiment_dir/attack_log.json"
        log "✓ Copied attack_log.json"
    else
        warn "⚠️ attack_log.json not found"
    fi
    
    # Collect container logs only if they contain useful information
    log "Checking container logs for useful information..."
    
    # Check if attacker logs contain useful info
    local attacker_logs=$(docker logs securitylogs-attacker 2>&1 | wc -l)
    log "Attacker logs line count: $attacker_logs"
    
    # Always collect attacker logs for debugging, even if minimal
    if docker logs securitylogs-attacker > "$experiment_dir/securitylogs-attacker_logs.txt" 2>&1; then
        log "✓ Copied attacker logs ($attacker_logs lines)"
    else
        warn "⚠️ Failed to copy attacker logs"
    fi
    
    # Check if webapp logs contain useful info (usually just startup logs)
    local webapp_logs=$(docker logs securitylogs-webapp 2>&1 | wc -l)
    log "Webapp logs line count: $webapp_logs"
    
    if [ "$webapp_logs" -gt 10 ]; then
        docker logs securitylogs-webapp > "$experiment_dir/securitylogs-webapp_logs.txt" 2>&1
        log "✓ Copied webapp logs ($webapp_logs lines)"
    else
        # Still collect webapp logs for debugging
        docker logs securitylogs-webapp > "$experiment_dir/securitylogs-webapp_logs.txt" 2>&1
        log "⚠️ Webapp logs are minimal ($webapp_logs lines), but collected for debugging"
    fi
    
    # Collect PCAP files
    log "Collecting PCAP files..."
    local pcap_filename="low-and-slow-sqli_${variant}_${timestamp}.pcap"
    
    if [ -f "$PCAP_DIR/$pcap_filename" ] && [ -s "$PCAP_DIR/$pcap_filename" ]; then
        cp "$PCAP_DIR/$pcap_filename" "$experiment_dir/"
        log "✓ Copied $pcap_filename ($(du -h "$PCAP_DIR/$pcap_filename" | cut -f1))"
    else
        warn "⚠️ $pcap_filename not found or empty"
    fi
    
    # Generate experiment summary
    generate_experiment_summary "$experiment_dir" "$variant" "$timestamp"
}

# Function to generate experiment summary
generate_experiment_summary() {
    local experiment_dir="$1"
    local variant="$2"
    local timestamp="$3"
    
    log "Generating experiment summary..."
    
    cat > "$experiment_dir/experiment_summary.md" << EOF
# Single Variant Experiment Summary

**Experiment Timestamp:** $timestamp  
**Run Directory:** $experiment_dir

## Experiment Configuration

- **Variant:** $variant
- **Scenario:** $SCENARIO_NAME
- **Attack Duration:** ${ATTACK_DURATION:-300} seconds
- **Benign Duration:** ${BENIGN_DURATION:-600} seconds
- **Warmup Time:** ${WARMUP_TIME:-30} seconds

## Experiment Details

- **Type:** Single Variant (Isolated)
- **Data Collection:** Complete logs and PCAP files
- **Isolation:** Complete network isolation for this variant

## Variant Configuration

EOF
    
    case "$variant" in
        "stealthy")
            echo "- Stealthy (RISK=1, LEVEL=1) - Very slow and stealthy attack" >> "$experiment_dir/experiment_summary.md"
            ;;
        "moderate")
            echo "- Moderate (RISK=1, LEVEL=2) - Balanced attack" >> "$experiment_dir/experiment_summary.md"
            ;;
        "aggressive")
            echo "- Aggressive (RISK=2, LEVEL=3) - Faster attack" >> "$experiment_dir/experiment_summary.md"
            ;;
    esac
    
    cat >> "$experiment_dir/experiment_summary.md" << EOF

## Files Collected

### Attack Data
- attack_log.json (detailed attack results)

### Network Traffic
EOF
    
    local pcap_filename="low-and-slow-sqli_${variant}_${timestamp}.pcap"
    if [ -f "$experiment_dir/$pcap_filename" ]; then
        echo "- $pcap_filename" >> "$experiment_dir/experiment_summary.md"
    fi
    
    cat >> "$experiment_dir/experiment_summary.md" << EOF

## Analysis Commands

\`\`\`bash
# Analyze PCAP file for this variant
tcpdump -r $experiment_dir/$pcap_filename -c 50

# View attack results
cat $experiment_dir/attack_log.json | jq '.'

# Run multi-source logger
python3 ../../automation/multi_source_logger.py
\`\`\`

## Isolation Benefits

This experiment ensures complete data isolation:
- Single variant execution
- Dedicated tcpdump container
- No cross-contamination with other variants
- Clean dataset for analysis

EOF
    
    log "✓ Experiment summary generated: $experiment_dir/experiment_summary.md"
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
    echo -e "${BLUE}SecurityLogs Single Variant Experiment${NC}"
    echo "============================================="
    echo ""
    
    # Parse command line arguments
    parse_args "$@"
    
    # Set default values
    ATTACK_DURATION=${ATTACK_DURATION:-300}
    BENIGN_DURATION=${BENIGN_DURATION:-600}
    WARMUP_TIME=${WARMUP_TIME:-30}
    
    # Validate variant
    valid_variants=("stealthy" "moderate" "aggressive")
    valid_variant=false
    for v in "${valid_variants[@]}"; do
        if [ "$VARIANT_NAME" = "$v" ]; then
            valid_variant=true
            break
        fi
    done
    
    if [ "$valid_variant" = false ]; then
        error "Invalid variant '$VARIANT_NAME'"
        echo "Valid variants: ${valid_variants[*]}"
        exit 1
    fi
    
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
    
    log "=== Starting Single Variant Experiment ==="
    log "Variant: $VARIANT_NAME"
    log "Timestamp: $TIMESTAMP"
    log "Experiment Directory: $EXPERIMENT_DIR"
    log "Attack Duration: $ATTACK_DURATION seconds"
    log "Benign Duration: $BENIGN_DURATION seconds"
    log "Warmup Time: $WARMUP_TIME seconds"
    echo ""
    
    # Start isolated tcpdump
    local tcpdump_container=$(start_isolated_tcpdump "$VARIANT_NAME" "$TIMESTAMP")
    
    # Start benign traffic with timeout
    log "Starting benign traffic with timeout..."
    local benign_pid=$(start_benign_traffic "$BENIGN_DURATION")
    
    # Wait for warmup
    log "Waiting for benign traffic warmup ($WARMUP_TIME seconds)..."
    sleep "$WARMUP_TIME"
    
    # Run attack variant with timeout
    log "Starting attack variant with timeout..."
    timeout "$ATTACK_DURATION" docker exec securitylogs-attacker python3 /opt/scripts/container_attack.py \
        --risk 1 --level 1 --variant "$VARIANT_NAME" &
    
    local attack_pid=$!
    log "✓ Attack started (PID: $attack_pid)"
    
    # Wait for attack to complete or timeout
    log "Waiting for attack to complete (max $ATTACK_DURATION seconds)..."
    wait $attack_pid 2>/dev/null || log "Attack completed or timed out"
    
    # Stop benign traffic
    stop_benign_traffic
    
    # Stop tcpdump
    stop_isolated_tcpdump "$tcpdump_container"
    
    # Collect data
    collect_data "$EXPERIMENT_DIR" "$VARIANT_NAME" "$TIMESTAMP"
    
    # Final summary
    echo ""
    echo -e "${BLUE}Single Variant Experiment Complete${NC}"
    echo "======================================="
    echo "✓ Variant: $VARIANT_NAME"
    echo "✓ Attack executed"
    echo "✓ Data collected in: $EXPERIMENT_DIR"
    echo "✓ Complete isolation maintained"
    echo ""
    echo "Check the experiment results in: $EXPERIMENT_DIR"
}

# Run main function
main "$@" 