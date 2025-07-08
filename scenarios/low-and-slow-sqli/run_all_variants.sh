#!/bin/bash

# Batch Variant Execution Script
# Runs all variants of the low-and-slow-sqli scenario

set -e

# Load configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config/scenario.env" 2>/dev/null || true

# Default values
PARALLEL=${PARALLEL:-false}
CLEANUP=${CLEANUP:-true}
TIMEOUT=${EXPERIMENT_TIMEOUT:-3600}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --parallel)
            PARALLEL=true
            shift
            ;;
        --no-cleanup)
            CLEANUP=false
            shift
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --parallel          Run variants in parallel"
            echo "  --no-cleanup        Don't clean up after each variant"
            echo "  --timeout SECONDS   Timeout for each variant"
            echo "  --help             Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] BATCH: $1"
}

run_variant() {
    local variant="$1"
    local variant_dir="$SCRIPT_DIR/variants/$variant"
    
    log_message "Starting variant: $variant"
    
    # Create variant-specific directories
    mkdir -p "$variant_dir/pcap_data"
    mkdir -p "$variant_dir/logs"
    mkdir -p "$variant_dir/output"
    
    # Load variant configuration
    local nmap_rate=$(yq e ".variants.$variant.nmap_rate" "$SCRIPT_DIR/config/variants.yml")
    local sql_delay=$(yq e ".variants.$variant.sql_delay" "$SCRIPT_DIR/config/variants.yml")
    local protocol_mix=$(yq e ".variants.$variant.protocol_mix" "$SCRIPT_DIR/config/variants.yml")
    local netem_profile=$(yq e ".variants.$variant.netem_profile" "$SCRIPT_DIR/config/variants.yml")
    local attack_duration=$(yq e ".variants.$variant.attack_duration" "$SCRIPT_DIR/config/variants.yml")
    local benign_duration=$(yq e ".variants.$variant.benign_duration" "$SCRIPT_DIR/config/variants.yml")
    
    # Export variant-specific environment variables
    export NMAP_RATE="$nmap_rate"
    export SQL_DELAY="$sql_delay"
    export PROTOCOL_MIX="$protocol_mix"
    export NETEM_PROFILE="$netem_profile"
    export ATTACK_DURATION="$attack_duration"
    export BENIGN_DURATION="$benign_duration"
    export SCENARIO_VARIANT="$variant"
    
    log_message "Variant $variant configuration:"
    log_message "  NMAP_RATE: $nmap_rate"
    log_message "  SQL_DELAY: $sql_delay"
    log_message "  PROTOCOL_MIX: $protocol_mix"
    log_message "  NETEM_PROFILE: $netem_profile"
    
    # Start containers
    log_message "Starting containers for variant $variant"
    cd "$SCRIPT_DIR"
    docker-compose up -d
    
    # Wait for containers to be ready
    log_message "Waiting for containers to be ready..."
    sleep 30
    
    # Apply network emulation
    log_message "Applying network emulation profile: $netem_profile"
    bash ../../control/apply_netem.sh --profile "$netem_profile"
    
    # Start benign traffic
    log_message "Starting benign traffic for variant $variant"
    docker exec securitylogs-webapp bash /opt/scripts/run_benign.sh \
        --protocol-mix "$protocol_mix" \
        --duration "$benign_duration" &
    BENIGN_PID=$!
    
    # Wait for benign traffic to start
    sleep 10
    
    # Start attack
    log_message "Starting attack for variant $variant"
    docker exec securitylogs-attacker bash /opt/scripts/run_attack.sh &
    ATTACK_PID=$!
    
    # Wait for attack to complete
    log_message "Waiting for attack to complete..."
    wait $ATTACK_PID
    
    # Wait for benign traffic to complete
    log_message "Waiting for benign traffic to complete..."
    wait $BENIGN_PID
    
    # Stop containers
    log_message "Stopping containers for variant $variant"
    docker-compose down
    
    # Copy results to variant directory
    log_message "Copying results for variant $variant"
    cp -r ../../pcap_data/low-and-slow-sqli/* "$variant_dir/pcap_data/" 2>/dev/null || true
    cp -r ../../logs/low-and-slow-sqli/* "$variant_dir/logs/" 2>/dev/null || true
    cp -r ../../output/low-and-slow-sqli/* "$variant_dir/output/" 2>/dev/null || true
    
    # Reset network emulation
    log_message "Resetting network emulation"
    bash ../../control/reset_netem.sh
    
    log_message "Variant $variant completed"
}

main() {
    log_message "Starting batch variant execution"
    log_message "Parallel execution: $PARALLEL"
    log_message "Cleanup: $CLEANUP"
    log_message "Timeout: $TIMEOUT seconds"
    
    # Get list of variants from configuration
    local variants=($(yq e '.execution_order[]' "$SCRIPT_DIR/config/variants.yml"))
    
    log_message "Found variants: ${variants[*]}"
    
    if [ "$PARALLEL" = true ]; then
        # Run variants in parallel
        log_message "Running variants in parallel"
        local pids=()
        
        for variant in "${variants[@]}"; do
            run_variant "$variant" &
            pids+=($!)
        done
        
        # Wait for all variants to complete
        log_message "Waiting for all variants to complete..."
        for pid in "${pids[@]}"; do
            wait $pid
        done
    else
        # Run variants sequentially
        log_message "Running variants sequentially"
        for variant in "${variants[@]}"; do
            run_variant "$variant"
        done
    fi
    
    log_message "All variants completed"
    
    # Generate summary report
    generate_summary_report
}

generate_summary_report() {
    log_message "Generating summary report"
    
    local report_file="$SCRIPT_DIR/batch_execution_report.txt"
    {
        echo "SecurityLogs Batch Execution Report"
        echo "=================================="
        echo "Timestamp: $(date)"
        echo "Scenario: $SCENARIO_NAME"
        echo "Total variants: $(yq e '.execution_order | length' "$SCRIPT_DIR/config/variants.yml")"
        echo ""
        echo "Variant Results:"
        echo "==============="
        
        for variant in $(yq e '.execution_order[]' "$SCRIPT_DIR/config/variants.yml"); do
            local variant_dir="$SCRIPT_DIR/variants/$variant"
            if [ -d "$variant_dir" ]; then
                local pcap_count=$(find "$variant_dir/pcap_data" -name "*.pcap" 2>/dev/null | wc -l)
                local log_count=$(find "$variant_dir/logs" -name "*.log" 2>/dev/null | wc -l)
                echo "  $variant: $pcap_count PCAP files, $log_count log files"
            else
                echo "  $variant: FAILED"
            fi
        done
        
        echo ""
        echo "Execution completed at: $(date)"
    } > "$report_file"
    
    log_message "Summary report saved to: $report_file"
}

# Cleanup function
cleanup() {
    log_message "Cleaning up batch execution..."
    cd "$SCRIPT_DIR"
    docker-compose down --remove-orphans 2>/dev/null || true
    bash ../../control/reset_netem.sh 2>/dev/null || true
    log_message "Cleanup completed"
}

# Set up signal handlers
trap cleanup EXIT INT TERM

# Main execution
main "$@" 