#!/bin/bash

# HTTP Traffic Module for Benign Traffic Generation
# Generates realistic HTTP traffic to simulate normal user behavior

set -e

# Load configuration
source /opt/config/scenario.env 2>/dev/null || true

# Default values
TARGET_URL=${TARGET_URL:-"http://victim-web"}
REQUEST_INTERVAL=${REQUEST_INTERVAL:-2}
TOTAL_DURATION=${BENIGN_TOTAL_DURATION:-2400}
LOG_FILE="/var/log/benign_http.log"

# HTTP endpoints to simulate
ENDPOINTS=(
    "/"
    "/index.php"
    "/login.php"
    "/search.php"
    "/products.php"
    "/about.php"
    "/contact.php"
    "/admin.php"
    "/robots.txt"
    "/favicon.ico"
    "/sitemap.xml"
)

# User agents for realistic traffic
USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"
)

# HTTP methods
HTTP_METHODS=("GET" "POST" "HEAD")

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] HTTP: $1" >> "$LOG_FILE"
}

generate_http_traffic() {
    local start_time=$(date +%s)
    local end_time=$((start_time + TOTAL_DURATION))
    
    log_message "Starting HTTP traffic generation for ${TOTAL_DURATION} seconds"
    
    while [ $(date +%s) -lt $end_time ]; do
        # Select random endpoint
        local endpoint=${ENDPOINTS[$((RANDOM % ${#ENDPOINTS[@]}))]}
        
        # Select random user agent
        local user_agent=${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}
        
        # Select random HTTP method
        local method=${HTTP_METHODS[$((RANDOM % ${#HTTP_METHODS[@]}))]}
        
        # Generate request
        case $method in
            "GET")
                if [[ "$endpoint" == "/search.php" ]]; then
                    # Add search parameters
                    local search_terms=("laptop" "phone" "tablet" "computer" "electronics")
                    local term=${search_terms[$((RANDOM % ${#search_terms[@]}))]}
                    curl -s -A "$user_agent" "${TARGET_URL}${endpoint}?q=${term}" > /dev/null 2>&1
                elif [[ "$endpoint" == "/login.php" ]]; then
                    # Simulate login attempts
                    local users=("user1" "user2" "admin" "test" "guest")
                    local user=${users[$((RANDOM % ${#users[@]}))]}
                    curl -s -A "$user_agent" "${TARGET_URL}${endpoint}?user=${user}&pass=password" > /dev/null 2>&1
                else
                    curl -s -A "$user_agent" "${TARGET_URL}${endpoint}" > /dev/null 2>&1
                fi
                ;;
            "POST")
                # Simulate form submissions
                curl -s -A "$user_agent" -X POST -d "name=test&email=test@example.com" "${TARGET_URL}${endpoint}" > /dev/null 2>&1
                ;;
            "HEAD")
                curl -s -A "$user_agent" -I "${TARGET_URL}${endpoint}" > /dev/null 2>&1
                ;;
        esac
        
        # Log the request
        log_message "Request: $method ${TARGET_URL}${endpoint}"
        
        # Random delay between requests
        local delay=$((RANDOM % REQUEST_INTERVAL + 1))
        sleep $delay
    done
    
    log_message "HTTP traffic generation completed"
}

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    generate_http_traffic
fi 