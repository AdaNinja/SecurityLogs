#!/bin/bash

# DNS Traffic Module for Benign Traffic Generation
# Generates realistic DNS queries to simulate normal network activity

set -e

# Load configuration
source /opt/config/scenario.env 2>/dev/null || true

# Default values
DNS_SERVER=${DNS_SERVER:-"8.8.8.8"}
REQUEST_INTERVAL=${REQUEST_INTERVAL:-5}
TOTAL_DURATION=${BENIGN_TOTAL_DURATION:-2400}
LOG_FILE="/var/log/benign_dns.log"

# Common domains for realistic DNS queries
DOMAINS=(
    "google.com"
    "facebook.com"
    "youtube.com"
    "amazon.com"
    "netflix.com"
    "github.com"
    "stackoverflow.com"
    "reddit.com"
    "twitter.com"
    "linkedin.com"
    "microsoft.com"
    "apple.com"
    "cloudflare.com"
    "wikipedia.org"
    "baidu.com"
    "qq.com"
    "taobao.com"
    "alibaba.com"
    "jd.com"
    "weibo.com"
)

# DNS record types
RECORD_TYPES=("A" "AAAA" "MX" "NS" "TXT" "CNAME")

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] DNS: $1" >> "$LOG_FILE"
}

generate_dns_traffic() {
    local start_time=$(date +%s)
    local end_time=$((start_time + TOTAL_DURATION))
    
    log_message "Starting DNS traffic generation for ${TOTAL_DURATION} seconds"
    
    while [ $(date +%s) -lt $end_time ]; do
        # Select random domain
        local domain=${DOMAINS[$((RANDOM % ${#DOMAINS[@]}))]}
        
        # Select random record type
        local record_type=${RECORD_TYPES[$((RANDOM % ${#RECORD_TYPES[@]}))]}
        
        # Generate DNS query using dig
        if command -v dig >/dev/null 2>&1; then
            dig @$DNS_SERVER $domain $record_type +short > /dev/null 2>&1
            log_message "Query: $record_type $domain"
        else
            # Fallback to nslookup
            nslookup -type=$record_type $domain $DNS_SERVER > /dev/null 2>&1
            log_message "Query: $record_type $domain (nslookup)"
        fi
        
        # Random delay between queries
        local delay=$((RANDOM % REQUEST_INTERVAL + 2))
        sleep $delay
    done
    
    log_message "DNS traffic generation completed"
}

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    generate_dns_traffic
fi 