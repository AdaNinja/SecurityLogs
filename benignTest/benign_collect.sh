#!/bin/bash

# Benign Activity Log Collection Script
# Simulates normal user behavior and collects multi-source logs for baseline data

set -e

# Configuration
ROUNDS=3
DELAY_BETWEEN_ROUNDS=30
DELAY_BETWEEN_ACTIONS=5

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if containers are running
check_containers() {
    print_status "Checking if victim containers are running..."
    
    if ! docker ps | grep -q "docker_victim1_1"; then
        print_error "victim1 container is not running!"
        print_status "Please start the containers first: cd .. && docker-compose up -d"
        exit 1
    fi
    
    if ! docker ps | grep -q "docker_victim2_1"; then
        print_error "victim2 container is not running!"
        print_status "Please start the containers first: cd .. && docker-compose up -d"
        exit 1
    fi
    
    print_success "Both victim containers are running"
}

# Function to test network connectivity
test_connectivity() {
    print_status "Testing network connectivity between containers..."
    
    # Test victim1 -> victim2
    if docker exec docker_victim1_1 curl -s -o /dev/null -w "%{http_code}" http://docker_victim2_1:80 | grep -q "200"; then
        print_success "victim1 can reach victim2"
    else
        print_warning "victim1 cannot reach victim2"
    fi
    
    # Test victim2 -> victim1
    if docker exec docker_victim2_1 curl -s -o /dev/null -w "%{http_code}" http://docker_victim1_1:80 | grep -q "200"; then
        print_success "victim2 can reach victim1"
    else
        print_warning "victim2 cannot reach victim1"
    fi
}

# Function to simulate benign activities for victim1
simulate_victim1_activities() {
    local round=$1
    print_status "Simulating benign activities for victim1 (Round $round)..."
    
    # Create round directory
    mkdir -p "round${round}/victim1"

    # Simulate web browsing activities
    print_status "  Accessing common websites..."
    
    # Access Baidu
    docker exec docker_victim1_1 curl -s https://www.baidu.com > "round${round}/victim1/baidu.html"
    sleep $DELAY_BETWEEN_ACTIONS
    
    # Access Bilibili
    docker exec docker_victim1_1 curl -s https://www.bilibili.com > "round${round}/victim1/bilibili.html"
    sleep $DELAY_BETWEEN_ACTIONS
    
    # Access GitHub
    docker exec docker_victim1_1 curl -s https://github.com > "round${round}/victim1/github.html"
    sleep $DELAY_BETWEEN_ACTIONS
    
    # Access HTTPBin for testing
    docker exec docker_victim1_1 curl -s https://httpbin.org/get > "round${round}/victim1/httpbin.html"
    sleep $DELAY_BETWEEN_ACTIONS
    
    # Test internal communication
    docker exec docker_victim1_1 curl -s http://docker_victim2_1:80 > "round${round}/victim1/victim2_health.html"
    sleep $DELAY_BETWEEN_ACTIONS
    
    # Collect system logs
    print_status "  Collecting system logs..."
    docker exec docker_victim1_1 cat /var/log/syslog > "round${round}/victim1/syslog" 2>/dev/null || true
    
    # Create raw logs directory and collect audit logs
    mkdir -p "round${round}/victim1/raw"
    docker exec docker_victim1_1 cat /var/log/audit/audit.log > "round${round}/victim1/raw/audit.log" 2>/dev/null || true
    
    print_success "victim1 activities completed for round $round"
}

# Function to simulate benign activities for victim2
simulate_victim2_activities() {
    local round=$1
    print_status "Simulating benign activities for victim2 (Round $round)..."
    
    # Create round directory
    mkdir -p "round${round}/victim2"
    
    # Simulate different web browsing activities
    print_status "  Accessing different websites..."
    
    # Access Zhihu
    docker exec docker_victim2_1 curl -s https://www.zhihu.com > "round${round}/victim2/zhihu.html"
    sleep $DELAY_BETWEEN_ACTIONS
    
    # Access YouTube
    docker exec docker_victim2_1 curl -s https://www.youtube.com > "round${round}/victim2/youtube.html"
    sleep $DELAY_BETWEEN_ACTIONS
    
    # Access Stack Overflow
    docker exec docker_victim2_1 curl -s https://stackoverflow.com > "round${round}/victim2/stackoverflow.html"
    sleep $DELAY_BETWEEN_ACTIONS
    
    # Access HTTPBin IP endpoint
    docker exec docker_victim2_1 curl -s https://httpbin.org/ip > "round${round}/victim2/httpbin_ip.html"
    sleep $DELAY_BETWEEN_ACTIONS
    
    # Test internal communication
    docker exec docker_victim2_1 curl -s http://docker_victim1_1:25 > "round${round}/victim2/victim1_smtp.html"
    sleep $DELAY_BETWEEN_ACTIONS
    
    # Collect system logs
    print_status "  Collecting system logs..."
    docker exec docker_victim2_1 cat /var/log/syslog > "round${round}/victim2/syslog" 2>/dev/null || true
    
    # Create raw logs directory and collect audit logs
    mkdir -p "round${round}/victim2/raw"
    docker exec docker_victim2_1 cat /var/log/audit/audit.log > "round${round}/victim2/raw/audit.log" 2>/dev/null || true
    
    print_success "victim2 activities completed for round $round"
}

# Function to collect network traffic
collect_network_traffic() {
    local round=$1
    print_status "Collecting network traffic for round $round..."
    
    # Start tcpdump on victim1 (redirect output to avoid cluttering)
    docker exec docker_victim1_1 tcpdump -i any -w "/tmp/victim1_round${round}.pcap" >/dev/null 2>&1 &
    local victim1_pid=$!
    
    # Start tcpdump on victim2 (redirect output to avoid cluttering)
    docker exec docker_victim2_1 tcpdump -i any -w "/tmp/victim2_round${round}.pcap" >/dev/null 2>&1 &
    local victim2_pid=$!
    
    # Wait for activities to complete
    sleep 30
    
    # Stop tcpdump
    docker exec docker_victim1_1 pkill tcpdump >/dev/null 2>&1 || true
    docker exec docker_victim2_1 pkill tcpdump >/dev/null 2>&1 || true
    
    # Copy pcap files
    docker cp docker_victim1_1:/tmp/victim1_round${round}.pcap round${round}/victim1/ 2>/dev/null || true
    docker cp docker_victim2_1:/tmp/victim2_round${round}.pcap round${round}/victim2/ 2>/dev/null || true
    
    # Clean up
    docker exec docker_victim1_1 rm -f /tmp/victim1_round${round}.pcap 2>/dev/null || true
    docker exec docker_victim2_1 rm -f /tmp/victim2_round${round}.pcap 2>/dev/null || true
    
    print_success "Network traffic collection completed for round $round"
}

# Function to collect Linux host audit logs
collect_host_audit_logs() {
    local round=$1
    print_status "Collecting Linux host audit logs for round $round..."
    
    # Create host logs directory
    mkdir -p "round${round}/host_logs"
    
    # Collect audit logs from Linux host
    print_status "  Collecting audit logs..."
    
    # Get current audit log
    if [ -f /var/log/audit/audit.log ]; then
        cp /var/log/audit/audit.log "round${round}/host_logs/host_audit.log" 2>/dev/null || true
    fi
    
    # Get system logs
    if [ -f /var/log/syslog ]; then
        cp /var/log/syslog "round${round}/host_logs/host_syslog" 2>/dev/null || true
    fi
    
    # Get auth logs
    if [ -f /var/log/auth.log ]; then
        cp /var/log/auth.log "round${round}/host_logs/host_auth.log" 2>/dev/null || true
    fi
    
    # Get kernel logs
    dmesg > "round${round}/host_logs/host_dmesg.log" 2>/dev/null || true
    
    # Get process information
    ps aux > "round${round}/host_logs/host_processes.log" 2>/dev/null || true
    
    # Get network connections
    netstat -tuln > "round${round}/host_logs/host_netstat.log" 2>/dev/null || true
    ss -tuln > "round${round}/host_logs/host_ss.log" 2>/dev/null || true
    
    # Get Docker container information
    docker ps > "round${round}/host_logs/host_docker_ps.log" 2>/dev/null || true
    docker stats --no-stream > "round${round}/host_logs/host_docker_stats.log" 2>/dev/null || true
    
    print_success "Host audit logs collection completed for round $round"
}

# Main execution
main() {
    print_status "Starting benign activity log collection..."
    print_status "Configuration: $ROUNDS rounds, ${DELAY_BETWEEN_ROUNDS}s between rounds, ${DELAY_BETWEEN_ACTIONS}s between actions"
    
    # Check containers
    check_containers
    
    # Test connectivity
    test_connectivity
    
    # Run multiple rounds
    for round in $(seq 1 $ROUNDS); do
        print_status "=== Starting Round $round ==="
        
        # Start network traffic collection
        collect_network_traffic $round &
        local traffic_pid=$!
        
        # Simulate activities
        simulate_victim1_activities $round &
        simulate_victim2_activities $round &
        
        # Wait for all activities to complete
        wait
        
        # Wait for traffic collection to finish (ignore errors)
        wait $traffic_pid 2>/dev/null || true
        
        # Collect host audit logs
        collect_host_audit_logs $round
        
        print_success "Round $round completed"
        
        # Delay between rounds (except for the last round)
        if [ $round -lt $ROUNDS ]; then
            print_status "Waiting ${DELAY_BETWEEN_ROUNDS} seconds before next round..."
            sleep $DELAY_BETWEEN_ROUNDS
        fi
    done
    
    print_success "All rounds completed successfully!"
    print_status "Data collected in round1/, round2/, round3/ directories"
    print_status "Each directory contains victim1/ and victim2/ subdirectories with logs"
}

# Run main function
main "$@"