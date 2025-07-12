#!/bin/bash

# HTTP Traffic Generator
# Simulates normal HTTP traffic to web applications

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_HOST=${TARGET_HOST:-"localhost"}
TARGET_PORT=${TARGET_PORT:-"8080"}
DURATION=${DURATION:-300}
INTERVAL=${INTERVAL:-2}
USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"
)

# HTTP endpoints to simulate
ENDPOINTS=(
    "/"
    "/index.html"
    "/about"
    "/contact"
    "/products"
    "/services"
    "/blog"
    "/news"
    "/api/status"
    "/robots.txt"
    "/favicon.ico"
    "/css/style.css"
    "/js/main.js"
    "/images/logo.png"
)

# Function to log messages
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to get random user agent
get_random_user_agent() {
    local index=$((RANDOM % ${#USER_AGENTS[@]}))
    echo "${USER_AGENTS[$index]}"
}

# Function to get random endpoint
get_random_endpoint() {
    local index=$((RANDOM % ${#ENDPOINTS[@]}))
    echo "${ENDPOINTS[$index]}"
}

# Function to generate random delay
get_random_delay() {
    local min=${1:-1}
    local max=${2:-5}
    echo $((RANDOM % (max - min + 1) + min))
}

# Function to make HTTP request
make_http_request() {
    local endpoint="$1"
    local user_agent="$2"
    local method="$3"
    
    case "$method" in
        "GET")
            curl -s -o /dev/null -w "%{http_code}" \
                -H "User-Agent: $user_agent" \
                -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
                -H "Accept-Language: en-US,en;q=0.5" \
                -H "Accept-Encoding: gzip, deflate" \
                -H "Connection: keep-alive" \
                -H "Upgrade-Insecure-Requests: 1" \
                "http://$TARGET_HOST:$TARGET_PORT$endpoint" 2>/dev/null || echo "000"
            ;;
        "POST")
            curl -s -o /dev/null -w "%{http_code}" \
                -H "User-Agent: $user_agent" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
                -d "name=test&email=test@example.com&message=Hello" \
                -X POST \
                "http://$TARGET_HOST:$TARGET_PORT$endpoint" 2>/dev/null || echo "000"
            ;;
        *)
            echo "000"
            ;;
    esac
}

# Function to simulate realistic HTTP traffic
simulate_http_traffic() {
    local duration="$1"
    local interval="$2"
    local start_time=$(date +%s)
    local request_count=0
    local success_count=0
    
    log "Starting HTTP traffic simulation..."
    log "Target: http://$TARGET_HOST:$TARGET_PORT"
    log "Duration: $duration seconds"
    log "Interval: $interval seconds"
    echo ""
    
    while true; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        
        if [ $elapsed -ge $duration ]; then
            break
        fi
        
        # Get random parameters
        local endpoint=$(get_random_endpoint)
        local user_agent=$(get_random_user_agent)
        local method="GET"
        
        # 10% chance of POST request
        if [ $((RANDOM % 10)) -eq 0 ]; then
            method="POST"
        fi
        
        # Make HTTP request
        local response_code=$(make_http_request "$endpoint" "$user_agent" "$method")
        request_count=$((request_count + 1))
        
        # Log request
        if [ "$response_code" = "200" ] || [ "$response_code" = "404" ] || [ "$response_code" = "500" ]; then
            success_count=$((success_count + 1))
            log "HTTP $method $endpoint -> $response_code"
        else
            warn "HTTP $method $endpoint -> $response_code (failed)"
        fi
        
        # Random delay between requests
        local delay=$(get_random_delay 1 3)
        sleep $delay
    done
    
    log "HTTP traffic simulation completed"
    log "Total requests: $request_count"
    log "Successful requests: $success_count"
    log "Success rate: $((success_count * 100 / request_count))%"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help message"
    echo "  -d, --duration SEC      Duration in seconds (default: 300)"
    echo "  -i, --interval SEC      Interval between requests (default: 2)"
    echo "  -t, --target HOST       Target host (default: localhost)"
    echo "  -p, --port PORT         Target port (default: 8080)"
    echo ""
    echo "Examples:"
    echo "  $0 -d 600               # Run for 10 minutes"
    echo "  $0 -i 1 -d 300         # Run for 5 minutes with 1s intervals"
    echo "  $0 -t 192.168.1.100    # Target specific host"
}

# Function to parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -d|--duration)
                DURATION="$2"
                shift 2
                ;;
            -i|--interval)
                INTERVAL="$2"
                shift 2
                ;;
            -t|--target)
                TARGET_HOST="$2"
                shift 2
                ;;
            -p|--port)
                TARGET_PORT="$2"
                shift 2
                ;;
            *)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Main execution
main() {
    echo "HTTP Traffic Generator"
    echo "===================="
    echo ""
    
    # Parse command line arguments
    parse_args "$@"
    
    # Check if curl is available
    if ! command -v curl &> /dev/null; then
        echo "Error: curl is not installed"
        exit 1
    fi
    
    # Check if target is reachable
    if ! curl -s --connect-timeout 5 "http://$TARGET_HOST:$TARGET_PORT/" > /dev/null 2>&1; then
        warn "Target http://$TARGET_HOST:$TARGET_PORT/ is not reachable"
        warn "Continuing anyway..."
    fi
    
    # Start HTTP traffic simulation
    simulate_http_traffic "$DURATION" "$INTERVAL"
}

# Run main function
main "$@" 