#!/bin/bash

# DNS Proxy Setup Script
# Sets up dnsmasq as DNS proxy for detailed DNS traffic logging

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
DNS_PROXY_PORT=5353
DNS_LOG_FILE="/var/log/dns_proxy.log"
DNS_CONFIG_FILE="/etc/dnsmasq.conf"

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to install dnsmasq
install_dnsmasq() {
    log "Installing dnsmasq..."
    
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update
        sudo apt-get install -y dnsmasq
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y dnsmasq
    else
        error "Unsupported package manager"
        exit 1
    fi
}

# Function to configure dnsmasq
configure_dnsmasq() {
    log "Configuring dnsmasq..."
    
    # Create backup of existing config
    if [ -f "$DNS_CONFIG_FILE" ]; then
        sudo cp "$DNS_CONFIG_FILE" "${DNS_CONFIG_FILE}.backup"
    fi
    
    # Create new dnsmasq configuration
    sudo tee "$DNS_CONFIG_FILE" > /dev/null << EOF
# DNS Proxy Configuration for SecurityLogs
# Detailed logging for DNS traffic analysis

# Basic settings
port=$DNS_PROXY_PORT
bind-interfaces
listen-address=0.0.0.0
no-resolv
no-poll

# Upstream DNS servers
server=8.8.8.8
server=8.8.4.4
server=1.1.1.1

# Logging configuration
log-queries
log-facility=/var/log/dnsmasq.log
log-async=20

# Cache settings
cache-size=1000
neg-ttl=3600
local-ttl=3600

# Query logging format
log-queries=extra

# Enable detailed logging
log-dhcp
log-tag=dns_proxy

# Security settings
no-hosts
no-negcache
no-ping
EOF

    log "DNS proxy configuration created"
}

# Function to start DNS proxy
start_dns_proxy() {
    log "Starting DNS proxy..."
    
    # Stop existing dnsmasq if running
    sudo systemctl stop dnsmasq 2>/dev/null || true
    sudo pkill dnsmasq 2>/dev/null || true
    
    # Start dnsmasq with our configuration
    sudo dnsmasq -C "$DNS_CONFIG_FILE" -d &
    DNS_PROXY_PID=$!
    
    log "DNS proxy started (PID: $DNS_PROXY_PID)"
    log "Listening on port $DNS_PROXY_PORT"
    
    # Wait for startup
    sleep 2
    
    # Test DNS proxy
    if dig @127.0.0.1 -p $DNS_PROXY_PORT google.com +short >/dev/null 2>&1; then
        log "DNS proxy is working correctly"
    else
        warn "DNS proxy test failed"
    fi
}

# Function to stop DNS proxy
stop_dns_proxy() {
    log "Stopping DNS proxy..."
    
    if [ ! -z "$DNS_PROXY_PID" ]; then
        kill $DNS_PROXY_PID 2>/dev/null || true
    fi
    
    sudo pkill dnsmasq 2>/dev/null || true
    log "DNS proxy stopped"
}

# Function to collect DNS logs
collect_dns_logs() {
    log "Collecting DNS proxy logs..."
    
    OUTPUT_DIR="data/raw/dns_logs"
    mkdir -p "$OUTPUT_DIR"
    
    # Collect dnsmasq logs
    if [ -f "/var/log/dnsmasq.log" ]; then
        sudo cp /var/log/dnsmasq.log "$OUTPUT_DIR/dns_proxy_$(date +%Y%m%d_%H%M%S).log"
        log "DNS logs saved to $OUTPUT_DIR/"
    fi
    
    # Parse and convert to JSONL format
    python3 scripts/data_processing/parse_dns_logs.py "$OUTPUT_DIR/dns_proxy_$(date +%Y%m%d_%H%M%S).log"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  install    - Install and configure DNS proxy"
    echo "  start      - Start DNS proxy"
    echo "  stop       - Stop DNS proxy"
    echo "  collect    - Collect DNS logs"
    echo "  status     - Show DNS proxy status"
    echo "  help       - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 install    # Install and configure"
    echo "  $0 start      # Start proxy"
    echo "  $0 collect    # Collect logs"
}

# Main script logic
case "${1:-help}" in
    install)
        install_dnsmasq
        configure_dnsmasq
        ;;
    start)
        start_dns_proxy
        ;;
    stop)
        stop_dns_proxy
        ;;
    collect)
        collect_dns_logs
        ;;
    status)
        if pgrep dnsmasq >/dev/null; then
            log "DNS proxy is running"
            ps aux | grep dnsmasq | grep -v grep
        else
            warn "DNS proxy is not running"
        fi
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        error "Unknown command: $1"
        show_usage
        exit 1
        ;;
esac 