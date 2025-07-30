#!/bin/bash
# Experiment controller for RAS security logs
# This script provides precise control over container startup based on experiment type

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$(dirname "$SCRIPT_DIR")"
RAS_DIR="$(dirname "$SCENARIO_DIR")"
OUTPUT_DIR="$SCENARIO_DIR/out"
EXPERIMENT_NAME=""
EXPERIMENT_DURATION=300
CLEAN_DATA="false"

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
    echo "  -n, --name EXPERIMENT_NAME     Experiment name (required for run)"
    echo "  -t, --type TYPE               Experiment type: attack, benign, mixed"
    echo "  -d, --duration SECONDS        Experiment duration in seconds (default: 300)"
    echo "  -a, --action ACTION           Action: start, stop, status, run"
    echo "  -c, --clean                   Clean old data before experiment"
    echo "  -h, --help                    Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 --type attack --action start"
    echo "  $0 --type benign --action start"
    echo "  $0 --type mixed --action start"
    echo "  $0 --name attack1 --type attack --action run --duration 600"
    echo "  $0 --name benign1 --type benign --action run --duration 300"
    echo "  $0 --name mixed1 --type mixed --action run --duration 900"
}

# Function to start attack experiment
start_attack_experiment() {
    echo -e "${BLUE}Starting ATTACK experiment...${NC}"
    echo -e "${GREEN}Containers: nginx, web, attacker${NC}"
    echo -e "${YELLOW}Disabled: user container${NC}"
    
    # Create attack-specific compose file
    cat > "$SCENARIO_DIR/docker-compose.attack.yml" << EOF
version: '3.8'
services:
  nginx:
    image: nginx:alpine
    hostname: fancystore.com
    networks:
      edge:
        aliases:
          - fancystore.com
      appnet: {}
    volumes:
      - ./confs/nginx/:/etc/nginx/
      - ./out/nginx/:/var/log/nginx
    depends_on:
      - web

  web:
    image: bkimminich/juice-shop:latest
    networks: [appnet]
    expose:
      - "3000"

  attacker:
    image: kalilinux/kali-rolling:latest
    networks: [edge]
    environment:
      - TARGET_HOST=fancystore.com
      - TARGET_PORT=80
      - ATTACK_TYPE=sql_injection
      - ATTACK_PHASE=automated
    volumes:
      - ./confs/attacker/attack.sh:/attack.sh:ro
      - ./confs/attacker/attack_scripts/:/opt/scripts/:ro
      - ./out/attacker/:/opt/output/
      - ./out/logs/:/opt/logs/
      - ./out/attacker/:/log
    depends_on:
      - nginx
    command: ["bash", "-c", "apt-get update && apt-get install -y python3 python3-pip curl wget python3-requests python3-dnspython nmap dirb git sqlmap slowhttptest tcpdump && bash /attack.sh --target http://fancystore.com"]

networks:
  edge:
    driver: bridge
    name: ras-securitylogs-edge
  appnet:
    driver: bridge
    name: ras-securitylogs-appnet
EOF
    
    # Start attack environment
    cd "$SCENARIO_DIR"
    docker-compose -f docker-compose.attack.yml up -d
    
    echo -e "${GREEN}Attack experiment started${NC}"
}

# Function to start benign experiment
start_benign_experiment() {
    echo -e "${BLUE}Starting BENIGN experiment...${NC}"
    echo -e "${GREEN}Containers: nginx, web, user${NC}"
    echo -e "${YELLOW}Disabled: attacker container${NC}"
    
    # Create benign-specific compose file
    cat > "$SCENARIO_DIR/docker-compose.benign.yml" << EOF
version: '3.8'
services:
  nginx:
    image: nginx:alpine
    hostname: fancystore.com
    networks:
      edge:
        aliases:
          - fancystore.com
      appnet: {}
    volumes:
      - ./confs/nginx/:/etc/nginx/
      - ./out/nginx/:/var/log/nginx
    depends_on:
      - web

  web:
    image: bkimminich/juice-shop:latest
    networks: [appnet]
    expose:
      - "3000"

  user:
    image: python:3.9-alpine
    networks: [edge]
    environment:
      - TARGET_HOST=fancystore.com
      - TARGET_PORT=80
    volumes:
      - ./confs/user/benign_enhanced.py:/benign_enhanced.py:ro
      - ./out/user/:/opt/output/
    depends_on:
      - nginx
    command: ["sh", "-c", "pip install requests && python /benign_enhanced.py http://fancystore.com"]

networks:
  edge:
    driver: bridge
    name: ras-securitylogs-edge
  appnet:
    driver: bridge
    name: ras-securitylogs-appnet
EOF
    
    # Start benign environment
    cd "$SCENARIO_DIR"
    docker-compose -f docker-compose.benign.yml up -d
    
    echo -e "${GREEN}Benign experiment started${NC}"
}

# Function to start mixed experiment
start_mixed_experiment() {
    echo -e "${BLUE}Starting MIXED experiment...${NC}"
    echo -e "${GREEN}Containers: nginx, web, attacker, user${NC}"
    echo -e "${YELLOW}Both attack and benign traffic will be generated${NC}"
    
    # Use the original docker-compose.yml
    cd "$SCENARIO_DIR"
    docker-compose up -d
    
    echo -e "${GREEN}Mixed experiment started${NC}"
}

# Function to stop experiment
stop_experiment() {
    local experiment_type="$1"
    
    echo -e "${BLUE}Stopping $experiment_type experiment...${NC}"
    
    cd "$SCENARIO_DIR"
    
    case "$experiment_type" in
        "attack")
            docker-compose -f docker-compose.attack.yml down
            rm -f docker-compose.attack.yml
            ;;
        "benign")
            docker-compose -f docker-compose.benign.yml down
            rm -f docker-compose.benign.yml
            ;;
        "mixed")
            docker-compose down
            ;;
    esac
    
    echo -e "${GREEN}Experiment stopped${NC}"
}

# Function to show experiment status
show_status() {
    local experiment_type="$1"
    
    echo -e "${BLUE}Status for $experiment_type experiment:${NC}"
    
    cd "$SCENARIO_DIR"
    
    case "$experiment_type" in
        "attack")
            if [[ -f "docker-compose.attack.yml" ]]; then
                docker-compose -f docker-compose.attack.yml ps
            else
                echo -e "${YELLOW}Attack experiment not running${NC}"
            fi
            ;;
        "benign")
            if [[ -f "docker-compose.benign.yml" ]]; then
                docker-compose -f docker-compose.benign.yml ps
            else
                echo -e "${YELLOW}Benign experiment not running${NC}"
            fi
            ;;
        "mixed")
            docker-compose ps
            ;;
    esac
}

# Function to check prerequisites
check_prerequisites() {
    echo -e "${BLUE}Checking prerequisites...${NC}"
    
    # Check if running as root (for network capture)
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root (use sudo) for network capture${NC}"
        exit 1
    fi
    
    # Check if tcpdump is available
    if ! command -v tcpdump &> /dev/null; then
        echo -e "${RED}Error: tcpdump not found. Please install tcpdump.${NC}"
        exit 1
    fi
    
    # Check if Docker is running
    if ! docker info &> /dev/null; then
        echo -e "${RED}Error: Docker is not running${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Prerequisites check passed${NC}"
}

# Function to clean old data
clean_old_data() {
    echo -e "${YELLOW}Cleaning old experiment data...${NC}"
    
    # Clean network captures
    if [[ -d "$OUTPUT_DIR/network" ]]; then
        rm -rf "$OUTPUT_DIR/network"/*
    fi
    
    # Clean logs
    if [[ -d "$OUTPUT_DIR/nginx" ]]; then
        rm -f "$OUTPUT_DIR/nginx"/*.log
    fi
    
    if [[ -d "$OUTPUT_DIR/attacker" ]]; then
        rm -f "$OUTPUT_DIR/attacker"/*
    fi
    
    if [[ -d "$OUTPUT_DIR/user" ]]; then
        rm -f "$OUTPUT_DIR/user"/*
    fi
    
    echo -e "${GREEN}Old data cleaned${NC}"
}

# Function to run attack experiment
run_attack_experiment() {
    local duration="$1"
    
    echo -e "${BLUE}Running attack experiment for ${duration}s...${NC}"
    
    # Start network capture
    "$SCRIPT_DIR/network_capture.sh" --start "$EXPERIMENT_NAME"
    
    # Wait for attack scripts to execute
    echo -e "${YELLOW}Waiting for attack execution...${NC}"
    sleep "$duration"
    
    # Stop network capture
    "$SCRIPT_DIR/network_capture.sh" --stop
    
    echo -e "${GREEN}Attack experiment completed${NC}"
}

# Function to run benign experiment
run_benign_experiment() {
    local duration="$1"
    
    echo -e "${BLUE}Running benign experiment for ${duration}s...${NC}"
    
    # Start network capture
    "$SCRIPT_DIR/network_capture.sh" --start "$EXPERIMENT_NAME"
    
    # Wait for benign scripts to execute
    echo -e "${YELLOW}Waiting for benign traffic generation...${NC}"
    sleep "$duration"
    
    # Stop network capture
    "$SCRIPT_DIR/network_capture.sh" --stop
    
    echo -e "${GREEN}Benign experiment completed${NC}"
}

# Function to run mixed experiment
run_mixed_experiment() {
    local duration="$1"
    
    echo -e "${BLUE}Running mixed experiment for ${duration}s...${NC}"
    
    # Start network capture
    "$SCRIPT_DIR/network_capture.sh" --start "$EXPERIMENT_NAME"
    
    # Wait for both attack and benign traffic
    echo -e "${YELLOW}Waiting for mixed traffic generation...${NC}"
    sleep "$duration"
    
    # Stop network capture
    "$SCRIPT_DIR/network_capture.sh" --stop
    
    echo -e "${GREEN}Mixed experiment completed${NC}"
}

# Function to collect experiment results
collect_results() {
    echo -e "${BLUE}Collecting experiment results...${NC}"
    
    # Create experiment results directory
    local results_dir="$OUTPUT_DIR/results/$EXPERIMENT_NAME"
    mkdir -p "$results_dir"
    
    # Copy network captures
    if [[ -d "$OUTPUT_DIR/network" ]]; then
        cp -r "$OUTPUT_DIR/network"/* "$results_dir/"
    fi
    
    # Copy nginx logs
    if [[ -d "$OUTPUT_DIR/nginx" ]]; then
        cp "$OUTPUT_DIR/nginx"/*.log "$results_dir/"
    fi
    
    # Copy attacker logs
    if [[ -d "$OUTPUT_DIR/attacker" ]]; then
        cp -r "$OUTPUT_DIR/attacker"/* "$results_dir/" 2>/dev/null || true
    fi
    
    # Copy user logs
    if [[ -d "$OUTPUT_DIR/user" ]]; then
        cp "$OUTPUT_DIR/user"/* "$results_dir/"
    fi
    
    # Copy audit logs
    if [[ -f "/var/log/audit/audit.log" ]]; then
        cp "/var/log/audit/audit.log" "$results_dir/audit.log"
        echo -e "${GREEN}Audit log copied${NC}"
    fi
    
    # Generate experiment summary
    cat > "$results_dir/experiment_summary.txt" << EOF
EXPERIMENT SUMMARY
==================
Name: $EXPERIMENT_NAME
Type: $EXPERIMENT_TYPE
Start Time: $(date -Iseconds)
End Time: $(date -Iseconds)
Duration: $EXPERIMENT_DURATION seconds

Files Collected:
- Network captures: $(ls "$results_dir"/*.pcap 2>/dev/null | wc -l)
- Nginx logs: $(ls "$results_dir"/*.log 2>/dev/null | wc -l)
- Attack logs: $(ls "$results_dir"/attack* 2>/dev/null | wc -l)
- User logs: $(ls "$results_dir"/benign* 2>/dev/null | wc -l)
- Audit logs: $(ls "$results_dir"/audit.log 2>/dev/null | wc -l)

EOF
    
    echo -e "${GREEN}Results collected in: $results_dir${NC}"
}

# Function to process logs
process_logs() {
    echo -e "${BLUE}Processing logs...${NC}"
    
    local results_dir="$OUTPUT_DIR/results/$EXPERIMENT_NAME"
    
    # Process nginx logs if available
    if [[ -f "$results_dir/detailed.log" ]]; then
        echo -e "${YELLOW}Processing nginx logs...${NC}"
        cd "$SCENARIO_DIR"
        python3 scripts/log_processor.py "$results_dir/detailed.log" \
            --output-csv "$results_dir/processed_logs.csv" \
            --output-json "$results_dir/processed_logs.json"
    fi
    
    echo -e "${GREEN}Log processing completed${NC}"
}

# Function to run complete experiment
run_complete_experiment() {
    local duration="$1"
    
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}EXPERIMENT: $EXPERIMENT_NAME${NC}"
    echo -e "${BLUE}TYPE: $EXPERIMENT_TYPE${NC}"
    echo -e "${BLUE}DURATION: ${duration}s${NC}"
    echo -e "${BLUE}========================================${NC}"
    
    # Check prerequisites
    check_prerequisites
    
    # Clean old data if requested
    if [[ "$CLEAN_DATA" == "true" ]]; then
        clean_old_data
    fi
    
    # Start environment
    case "$EXPERIMENT_TYPE" in
        "attack")
            start_attack_experiment
            ;;
        "benign")
            start_benign_experiment
            ;;
        "mixed")
            start_mixed_experiment
            ;;
    esac
    
    # Wait for containers to be ready
    echo -e "${YELLOW}Waiting for containers to be ready...${NC}"
    sleep 30
    
    # Run experiment based on type
    case "$EXPERIMENT_TYPE" in
        "attack")
            run_attack_experiment "$duration"
            ;;
        "benign")
            run_benign_experiment "$duration"
            ;;
        "mixed")
            run_mixed_experiment "$duration"
            ;;
    esac
    
    # Stop environment
    stop_experiment "$EXPERIMENT_TYPE"
    
    # Collect results
    collect_results
    
    # Process logs
    process_logs
    
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}EXPERIMENT COMPLETED: $EXPERIMENT_NAME${NC}"
    echo -e "${GREEN}Results available in: $OUTPUT_DIR/results/$EXPERIMENT_NAME${NC}"
    echo -e "${GREEN}========================================${NC}"
}

# Main script logic
EXPERIMENT_TYPE=""
ACTION=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--name)
            EXPERIMENT_NAME="$2"
            shift 2
            ;;
        -t|--type)
            EXPERIMENT_TYPE="$2"
            shift 2
            ;;
        -d|--duration)
            EXPERIMENT_DURATION="$2"
            shift 2
            ;;
        -a|--action)
            ACTION="$2"
            shift 2
            ;;
        -c|--clean)
            CLEAN_DATA="true"
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_usage
            exit 1
            ;;
    esac
done

# Validate parameters based on action
if [[ "$ACTION" == "run" ]]; then
    if [[ -z "$EXPERIMENT_NAME" ]] || [[ -z "$EXPERIMENT_TYPE" ]]; then
        echo -e "${RED}Error: Experiment name and type are required for 'run' action${NC}"
        show_usage
        exit 1
    fi
elif [[ -z "$EXPERIMENT_TYPE" ]] || [[ -z "$ACTION" ]]; then
    echo -e "${RED}Error: Both experiment type and action are required${NC}"
    show_usage
    exit 1
fi

# Validate experiment type
case "$EXPERIMENT_TYPE" in
    "attack"|"benign"|"mixed")
        ;;
    *)
        echo -e "${RED}Error: Invalid experiment type: $EXPERIMENT_TYPE${NC}"
        echo -e "${YELLOW}Valid types: attack, benign, mixed${NC}"
        exit 1
        ;;
esac

# Validate action
case "$ACTION" in
    "start"|"stop"|"status"|"run")
        ;;
    *)
        echo -e "${RED}Error: Invalid action: $ACTION${NC}"
        echo -e "${YELLOW}Valid actions: start, stop, status, run${NC}"
        exit 1
        ;;
esac

# Execute action
case "$ACTION" in
    "start")
        case "$EXPERIMENT_TYPE" in
            "attack")
                start_attack_experiment
                ;;
            "benign")
                start_benign_experiment
                ;;
            "mixed")
                start_mixed_experiment
                ;;
        esac
        ;;
    "stop")
        stop_experiment "$EXPERIMENT_TYPE"
        ;;
    "status")
        show_status "$EXPERIMENT_TYPE"
        ;;
    "run")
        run_complete_experiment "$EXPERIMENT_DURATION"
        ;;
esac 