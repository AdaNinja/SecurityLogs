#!/bin/bash

# Clean script for CyberRange experiments
# Clears all logs, output files, and containers before running new experiments

set -e

echo "Cleaning CyberRange experiment data..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Stop and remove containers
print_status $BLUE "Stopping and removing containers..."
if command -v docker &> /dev/null; then
    # Stop all running containers (only our scenario containers)
    docker ps -q --filter "name=juice-shop|nginx|attacker|benign_user" | xargs -r docker stop 2>/dev/null || true
    
    # Remove all containers (only our scenario containers)
    docker ps -aq --filter "name=juice-shop|nginx|attacker|benign_user" | xargs -r docker rm 2>/dev/null || true
    
    print_status $GREEN "Containers cleaned"
else
    print_status $YELLOW "Docker not found, skipping container cleanup"
fi

# Clean logs directory
print_status $BLUE "Cleaning logs directory..."
if [[ -d "logs" ]]; then
    rm -rf logs/*
    print_status $GREEN "Logs directory cleaned"
else
    print_status $YELLOW "Logs directory not found"
fi

# Clean output directory
print_status $BLUE "Cleaning output directory..."
if [[ -d "output" ]]; then
    rm -rf output/*
    print_status $GREEN "Output directory cleaned"
else
    print_status $YELLOW "Output directory not found"
fi

# Clean any remaining log files in root
print_status $BLUE "Cleaning log files in root directory..."
rm -f *.log 2>/dev/null || true
rm -f *.csv 2>/dev/null || true
rm -f *.pcap 2>/dev/null || true
print_status $GREEN "Root directory log files cleaned"

# Clean Docker networks (optional - be careful with this)
print_status $BLUE "Cleaning unused Docker networks..."
if command -v docker &> /dev/null; then
    # Only remove networks created by our scenarios
    docker network ls --filter "name=internal-net" -q | xargs -r docker network rm 2>/dev/null || true
    docker network ls --filter "name=external-net" -q | xargs -r docker network rm 2>/dev/null || true
    print_status $GREEN "Docker networks cleaned"
fi

# Clean Docker images (optional - removes unused images)
print_status $BLUE "Cleaning unused Docker images..."
if command -v docker &> /dev/null; then
    docker image prune -f 2>/dev/null || true
    print_status $GREEN "Unused Docker images cleaned"
fi

print_status $GREEN "Cleanup completed successfully!"
print_status $BLUE "You can now run a new experiment with: python3 run_scenario.py --config scenarios/your_scenario.yaml" 