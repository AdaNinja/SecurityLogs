#!/bin/bash

# RAS Startup Script
# Handles container startup and permission management for WAF and Vanilla scenarios

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Global variables
SCENARIO=""
SNIFF_BRIDGE=""
CAPTURE_PID=""
PCAP_FILE=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[RAS]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Function to validate scenario
validate_scenario() {
    if [ -z "$SCENARIO" ]; then
        error "Scenario not specified. Use 'waf', 'vanilla', or 'securitylogs'"
        show_help
        exit 1
    fi
    
    if [ "$SCENARIO" != "waf" ] && [ "$SCENARIO" != "vanilla" ] && [ "$SCENARIO" != "securitylogs" ]; then
        error "Invalid scenario: $SCENARIO. Use 'waf', 'vanilla', or 'securitylogs'"
        exit 1
    fi
    
    if [ ! -d "scenario-$SCENARIO" ]; then
        error "Scenario directory 'scenario-$SCENARIO' not found"
        exit 1
    fi
}

# Function to get available bridges for current scenario
get_available_bridges() {
    local scenario_project="ras-$SCENARIO"
    local edge_bridge=$(docker network inspect "${scenario_project}_edge" --format '{{.Id}}' 2>/dev/null | cut -c1-12)
    local appnet_bridge=$(docker network inspect "${scenario_project}_appnet" --format '{{.Id}}' 2>/dev/null | cut -c1-12)
    
    if [ -n "$edge_bridge" ] && [ -n "$appnet_bridge" ]; then
        echo "Available bridges for $SCENARIO scenario:"
        echo "  edge    : br-$edge_bridge (attacker, shopper, nginx communication)"
        echo "  appnet  : br-$appnet_bridge (nginx to web service communication)"
        echo "  both    : capture both networks"
    else
        warn "No networks found. Make sure containers are running."
    fi
}

# Function to start packet capture
start_packet_capture() {
    if [ -z "$SNIFF_BRIDGE" ]; then
        return 0  # No packet capture requested
    fi
    
    local scenario_project="ras-$SCENARIO"
    local edge_bridge=$(docker network inspect "${scenario_project}_edge" --format '{{.Id}}' 2>/dev/null | cut -c1-12)
    local appnet_bridge=$(docker network inspect "${scenario_project}_appnet" --format '{{.Id}}' 2>/dev/null | cut -c1-12)
    
    if [ -z "$edge_bridge" ] || [ -z "$appnet_bridge" ]; then
        error "Could not find Docker networks for scenario: $SCENARIO"
        return 1
    fi
    
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local pcap_dir="scenario-$SCENARIO/out/pcap"
    mkdir -p "$pcap_dir"
    
    case "$SNIFF_BRIDGE" in
        "edge")
            PCAP_FILE="$pcap_dir/edge-network-$timestamp.pcap"
            log "Starting packet capture on edge network (br-$edge_bridge)..."
            sudo tcpdump -i "br-$edge_bridge" -w "$PCAP_FILE" -s 0 > /dev/null 2>&1 &
            CAPTURE_PID=$!
            ;;
        "appnet")
            PCAP_FILE="$pcap_dir/appnet-network-$timestamp.pcap"
            log "Starting packet capture on appnet (br-$appnet_bridge)..."
            sudo tcpdump -i "br-$appnet_bridge" -w "$PCAP_FILE" -s 0 > /dev/null 2>&1 &
            CAPTURE_PID=$!
            ;;
        "both")
            local edge_file="$pcap_dir/edge-network-$timestamp.pcap"
            local appnet_file="$pcap_dir/appnet-network-$timestamp.pcap"
            log "Starting packet capture on both networks..."
            sudo tcpdump -i "br-$edge_bridge" -w "$edge_file" -s 0 > /dev/null 2>&1 &
            local edge_pid=$!
            sudo tcpdump -i "br-$appnet_bridge" -w "$appnet_file" -s 0 > /dev/null 2>&1 &
            local appnet_pid=$!
            CAPTURE_PID="$edge_pid $appnet_pid"
            PCAP_FILE="$edge_file $appnet_file"
            ;;
        *)
            error "Invalid bridge name: $SNIFF_BRIDGE. Use 'edge', 'appnet', or 'both'"
            return 1
            ;;
    esac
    
    if [ -n "$CAPTURE_PID" ]; then
        log "✅ Packet capture started (PID: $CAPTURE_PID)"
        log "📁 Capture file(s): $PCAP_FILE"
        echo "$CAPTURE_PID" > "scenario-$SCENARIO/.capture_pid"
        echo "$PCAP_FILE" > "scenario-$SCENARIO/.capture_files"
    fi
}

# Function to stop packet capture
stop_packet_capture() {
    local scenario_pid_file="scenario-$SCENARIO/.capture_pid"
    local scenario_files_file="scenario-$SCENARIO/.capture_files"
    
    if [ -f "$scenario_pid_file" ]; then
        local pids=$(cat "$scenario_pid_file")
        if [ -n "$pids" ]; then
            log "Stopping packet capture..."
            for pid in $pids; do
                sudo kill "$pid" 2>/dev/null || true
            done
            
            if [ -f "$scenario_files_file" ]; then
                local files=$(cat "$scenario_files_file")
                log "📁 Capture files saved: $files"
            fi
            
            rm -f "$scenario_pid_file" "$scenario_files_file"
            log "✅ Packet capture stopped"
        fi
    fi
}

# Function to fix permissions
fix_permissions() {
    log "Fixing file permissions for scenario: $SCENARIO..."
    
    USER_ID=$(id -u)
    GROUP_ID=$(id -g)
    
    local scenario_dir="scenario-$SCENARIO"
    
    # Directories that might be created by Docker
    DIRS=("$scenario_dir/out")
    
    for dir in "${DIRS[@]}"; do
        if [ -d "$dir" ]; then
            log "Fixing permissions for $dir/"
            if sudo chown -R "$USER_ID:$GROUP_ID" "$dir" 2>/dev/null; then
                chmod -R 755 "$dir"
                log "✅ Fixed $dir/"
            else
                warn "Could not fix $dir/ (might need sudo access)"
            fi
        fi
    done
}

# Function to initialize project
init_project() {
    log "Initializing $SCENARIO scenario structure..."
    
    local scenario_dir="scenario-$SCENARIO"
    
    # Create necessary directories
    mkdir -p "$scenario_dir/out"/{nginx,waf,pcap}
    log "✅ $SCENARIO scenario structure initialized"
}

# Function to start containers
start_containers() {
    validate_scenario
    
    log "Starting $SCENARIO scenario containers..."
    
    cd "scenario-$SCENARIO"
    
    if docker-compose -p "ras-$SCENARIO" up -d; then
        log "✅ $SCENARIO scenario containers started successfully"
        
        # Give containers time to create files
        log "Waiting for containers to initialize..."
        sleep 5
        
        cd ..
        
        # Start packet capture if requested
        start_packet_capture
        
        # Fix any permission issues
        fix_permissions
        
        log "🎉 RAS $SCENARIO environment is ready!"
        echo ""
        log "📊 Container status:"
        docker-compose -p "ras-$SCENARIO" -f "scenario-$SCENARIO/docker-compose.yml" ps
        echo ""
        log "📁 Log directories:"
        ls -la "scenario-$SCENARIO/out/" 2>/dev/null || true
        
        # Show available bridges
        echo ""
        get_available_bridges
        
    else
        error "Failed to start $SCENARIO scenario containers"
        exit 1
    fi
}

# Function to stop containers and fix permissions
stop_containers() {
    validate_scenario
    
    log "Stopping $SCENARIO scenario containers..."
    
    # Stop packet capture first
    stop_packet_capture
    
    cd "scenario-$SCENARIO"
    docker-compose -p "ras-$SCENARIO" down
    cd ..
    
    fix_permissions
    log "✅ $SCENARIO scenario containers stopped and permissions fixed"
}

# Function to restart containers
restart_containers() {
    log "Restarting $SCENARIO scenario containers..."
    stop_containers
    start_containers
}

# Function to show logs
show_logs() {
    validate_scenario
    log "Showing $SCENARIO scenario container logs..."
    docker-compose -p "ras-$SCENARIO" -f "scenario-$SCENARIO/docker-compose.yml" logs -f
}

# Function to clean everything
clean_all() {
    if [ -n "$SCENARIO" ]; then
        validate_scenario
        log "Cleaning $SCENARIO scenario containers and volumes..."
        stop_packet_capture
        cd "scenario-$SCENARIO"
        docker-compose -p "ras-$SCENARIO" down -v
        cd ..
        sudo rm -rf "scenario-$SCENARIO/out/"
        log "✅ $SCENARIO scenario clean complete"
    else
        log "Cleaning all scenarios..."
        for scenario in waf vanilla; do
            if [ -d "scenario-$scenario" ]; then
                log "Cleaning scenario: $scenario"
                cd "scenario-$scenario"
                docker-compose -p "ras-$scenario" down -v 2>/dev/null || true
                cd ..
                sudo rm -rf "scenario-$scenario/out/" 2>/dev/null || true
            fi
        done
        log "✅ All scenarios cleaned"
    fi
}

# Function to show help
show_help() {
    echo "RAS Container Management Script"
    echo ""
    echo "Usage: $0 <scenario> [command] [options]"
    echo ""
    echo "Scenarios:"
echo "  waf              Use WAF-protected scenario"
echo "  vanilla          Use vanilla (no WAF) scenario"
echo "  securitylogs     Use SecurityLogs attack scenario"
    echo ""
    echo "Commands:"
    echo "  start [--sniff BRIDGE]  Initialize and start containers (default)"
    echo "                          Optional: start packet capture on specified bridge"
    echo "  stop                    Stop containers and packet capture"
    echo "  restart                 Restart containers"
    echo "  logs                    Show container logs"
    echo "  fix-permissions         Fix file ownership issues"
    echo "  clean                   Stop containers and remove all data"
    echo "  bridges                 Show available network bridges"
    echo "  help                    Show this help message"
    echo ""
    echo "Bridge options for --sniff:"
    echo "  edge                    Capture edge network (attacker, shopper, nginx)"
    echo "  appnet                  Capture app network (nginx to web service)"
    echo "  both                    Capture both networks"
    echo ""
    echo "Examples:"
echo "  $0 vanilla start                    # Start vanilla scenario"
echo "  $0 waf start --sniff edge          # Start WAF scenario with edge network capture"
echo "  $0 securitylogs start --sniff both # Start SecurityLogs scenario with capture"
echo "  $0 vanilla start --sniff both      # Start vanilla with capture on both networks"
echo "  $0 waf stop                        # Stop WAF scenario and any running captures"
echo "  $0 vanilla bridges                 # Show available bridges for vanilla scenario"
}

# Parse command line arguments
if [ $# -lt 1 ]; then
    error "Missing scenario argument"
    show_help
    exit 1
fi

SCENARIO="$1"
COMMAND="${2:-start}"

# Parse additional arguments
shift 2
while [ $# -gt 0 ]; do
    case $1 in
        --sniff)
            SNIFF_BRIDGE="$2"
            shift 2
            ;;
        *)
            error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Main script logic
case "$COMMAND" in
    "start")
        init_project
        start_containers
        ;;
    "stop")
        stop_containers
        ;;
    "restart")
        restart_containers
        ;;
    "logs")
        show_logs
        ;;
    "fix-permissions")
        validate_scenario
        fix_permissions
        ;;
    "clean")
        clean_all
        ;;
    "bridges")
        validate_scenario
        get_available_bridges
        ;;
    "help"|"-h"|"--help")
        show_help
        ;;
    *)
        error "Unknown command: $COMMAND"
        show_help
        exit 1
        ;;
esac
