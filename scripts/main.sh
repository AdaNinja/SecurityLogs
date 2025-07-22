#!/bin/bash

# SecurityLogs Main Control Script
# 统一的项目控制入口

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Function to show usage
show_usage() {
    cat << EOF
SecurityLogs Main Control Script

Usage: $0 <command> [options]

Commands:
    capture          - Start traffic capture and logging
    attack           - Run attack scenarios
    process          - Process and analyze logs
    network          - Manage network conditions
    utils            - Utility functions
    help             - Show this help message

Examples:
    $0 capture start
    $0 attack run
    $0 process etl
    $0 network apply
    $0 utils debug

For detailed help on each command:
    $0 <command> help
EOF
}

# Function to handle capture commands
handle_capture() {
    case "$1" in
        start)
            print_header "Starting Traffic Capture"
            bash "$SCRIPT_DIR/automation/capture.sh"
            ;;
        stop)
            print_header "Stopping Traffic Capture"
            # Add stop logic here
            ;;
        help)
            echo "Capture commands:"
            echo "  start - Start traffic capture and logging"
            echo "  stop  - Stop traffic capture"
            ;;
        *)
            print_error "Unknown capture command: $1"
            echo "Use: $0 capture help"
            exit 1
            ;;
    esac
}

# Function to handle attack commands
handle_attack() {
    case "$1" in
        run)
            print_header "Running Attack Scenarios"
            python3 "$SCRIPT_DIR/attack/container_attack.py"
            ;;
        recon)
            print_header "Running Reconnaissance"
            bash "$SCRIPT_DIR/attack/run_recon.sh"
            ;;
        sql)
            print_header "Running SQL Injection Attack"
            python3 "$SCRIPT_DIR/attack/sql_injection.py"
            ;;
        stealthy)
            print_header "Running Stealthy Attack Variant"
            bash "$SCRIPT_DIR/automation/run_variant.sh" "lowscan_stealthy"
            ;;
        moderate)
            print_header "Running Moderate Attack Variant"
            bash "$SCRIPT_DIR/automation/run_variant.sh" "lowscan_moderate"
            ;;
        aggressive)
            print_header "Running Aggressive Attack Variant"
            bash "$SCRIPT_DIR/automation/run_variant.sh" "lowscan_aggressive"
            ;;
        all)
            print_header "Running All Attack Variants"
            bash "$SCRIPT_DIR/automation/run_all_variants.sh"
            ;;
        help)
            echo "Attack commands:"
            echo "  run        - Run attack scenarios"
            echo "  recon      - Run reconnaissance"
            echo "  sql        - Run SQL injection attack"
            echo "  stealthy   - Run stealthy attack variant (RISK=1, LEVEL=1)"
            echo "  moderate   - Run moderate attack variant (RISK=1, LEVEL=2)"
            echo "  aggressive - Run aggressive attack variant (RISK=2, LEVEL=3)"
            echo "  all        - Run all attack variants sequentially"
            ;;
        *)
            print_error "Unknown attack command: $1"
            echo "Use: $0 attack help"
            exit 1
            ;;
    esac
}

# Function to handle process commands
handle_process() {
    case "$1" in
        etl)
            print_header "Running ETL Processing"
            python3 "$SCRIPT_DIR/data_processing/etl_host_logs.py"
            python3 "$SCRIPT_DIR/data_processing/etl_container_logs.py"
            python3 "$SCRIPT_DIR/data_processing/etl_application_logs.py"
            python3 "$SCRIPT_DIR/data_processing/etl_attack_logs.py"
            ;;
        merge)
            print_header "Merging Log Files"
            python3 "$SCRIPT_DIR/data_processing/merge_all_logs.py"
            ;;
        collect)
            print_header "Collecting Host Logs"
            python3 "$SCRIPT_DIR/data_processing/collect_host_logs.py"
            ;;
        help)
            echo "Process commands:"
            echo "  etl    - Run ETL processing"
            echo "  merge  - Merge log files"
            echo "  collect - Collect host logs"
            ;;
        *)
            print_error "Unknown process command: $1"
            echo "Use: $0 process help"
            exit 1
            ;;
    esac
}

# Function to handle network commands
handle_network() {
    case "$1" in
        apply)
            print_header "Applying Network Conditions"
            bash "$SCRIPT_DIR/network/apply_netem.sh"
            ;;
        reset)
            print_header "Resetting Network Conditions"
            bash "$SCRIPT_DIR/network/reset_netem.sh"
            ;;
        help)
            echo "Network commands:"
            echo "  apply - Apply network conditions"
            echo "  reset - Reset network conditions"
            ;;
        *)
            print_error "Unknown network command: $1"
            echo "Use: $0 network help"
            exit 1
            ;;
    esac
}

# Function to handle utils commands
handle_utils() {
    case "$1" in
        debug)
            print_header "Debugging Container Logs"
            bash "$SCRIPT_DIR/utils/debug_container_logs.sh"
            ;;
        convert)
            print_header "Converting PCAP Files"
            bash "$SCRIPT_DIR/utils/pcap_converter.sh"
            ;;
        dns-proxy)
            print_header "DNS Proxy Management"
            bash "$SCRIPT_DIR/automation/dns_proxy_setup.sh" "${2:-help}"
            ;;
        analyze-pcap)
            print_header "Enhanced PCAP Analysis"
            if [ -z "$2" ]; then
                print_error "Please specify PCAP file"
                echo "Usage: $0 utils analyze-pcap <pcap_file>"
                exit 1
            fi
            python3 "$SCRIPT_DIR/data_processing/enhanced_pcap_analyzer.py" "$2"
            ;;
        help)
            echo "Utility commands:"
            echo "  debug       - Debug container logs"
            echo "  convert     - Convert PCAP files"
            echo "  dns-proxy   - Manage DNS proxy (install/start/stop/collect)"
            echo "  analyze-pcap - Enhanced PCAP analysis"
            ;;
        *)
            print_error "Unknown utils command: $1"
            echo "Use: $0 utils help"
            exit 1
            ;;
    esac
}

# Main script logic
main() {
    # Change to project root
    cd "$PROJECT_ROOT"
    
    case "$1" in
        capture)
            handle_capture "$2"
            ;;
        attack)
            handle_attack "$2"
            ;;
        process)
            handle_process "$2"
            ;;
        network)
            handle_network "$2"
            ;;
        utils)
            handle_utils "$2"
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            print_error "Unknown command: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@" 