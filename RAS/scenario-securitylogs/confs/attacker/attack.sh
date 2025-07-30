#!/bin/bash
set -e

# Redirect all output to log file
exec > >(tee /log/attack.log) 2>&1

# Function to execute attacks from attack file
execute_attacks_from_file() {
    local attack_file="$1"
    local start_line="$2"
    local end_line="$3"
    local target="$4"
    
    echo "[START] Executing attacks from file at $(date)"
    echo "[*] Attack file: $attack_file"
    
    if [[ ! -f "$attack_file" ]]; then
        echo "[ERROR] Attack file not found: $attack_file"
        return 1
    fi
    
    # Count total lines in attack file
    local total_lines=$(wc -l < "$attack_file")
    echo "[*] Total lines in attack file: $total_lines"
    
    # Count actual attack payloads (excluding comments and empty lines)
    local attack_count=$(grep -v "^#" "$attack_file" | grep -v "^$" | grep -v "benign" | wc -l)
    echo "[*] Total attack payloads: $attack_count"
    
    # Determine payload range (based on actual payloads, not file lines)
    local payload_start=1
    local payload_end="$attack_count"
    
    if [[ -n "$start_line" && -n "$end_line" ]]; then
        payload_start="$start_line"
        payload_end="$end_line"
        echo "[*] Executing payloads $payload_start to $payload_end (out of $attack_count total payloads)"
    else
        echo "[*] Executing all payloads (1 to $payload_end)"
    fi
    
    # Execute attacks from file
    local line_num=0
    local payload_count=0
    local executed_count=0
    local success_count=0
    local failed_count=0
    
    while IFS='|' read -r attack_type method path data expected waf_mode description; do
        line_num=$((line_num + 1))
        
        # Skip comment lines and empty lines
        if [[ "$attack_type" =~ ^#.*$ || -z "$attack_type" ]]; then
            continue
        fi
        
        # Skip benign traffic (we handle it separately)
        if [[ "$attack_type" == "benign" ]]; then
            continue
        fi
        
        # Count this as a valid payload
        payload_count=$((payload_count + 1))
        
        # Skip payloads outside the specified range
        if [[ $payload_count -lt $payload_start || $payload_count -gt $payload_end ]]; then
            continue
        fi
        
        # Use structured logging format for better parsing
        echo "===ATTACK_START==="
        echo "PAYLOAD_ID: $payload_count"
        echo "LINE_NUM: $line_num"
        echo "ATTACK_TYPE: $attack_type"
        echo "DESCRIPTION: $description"
        echo "METHOD: $method"
        echo "PATH: $path"
        echo "DATA: $data"
        echo "EXPECTED: $expected"
        echo "WAF_MODE: $waf_mode"
        echo "TIMESTAMP: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "===ATTACK_START==="
        
        # Execute the attack based on type using real attack tools
        case "$attack_type" in
            "sql_injection")
                echo "  [REAL ATTACK] Using curl for SQL injection testing..."
                # Use curl for SQL injection testing (simplified version)
                response=$(curl -s -w "%{http_code}" \
                    -X "$method" \
                    -H "User-Agent: attacker" \
                    -H "Content-Type: application/json" \
                    -d "$data" \
                    "$target$path")
                
                http_code=$(echo "$response" | tail -c 4)
                response_body=$(echo "$response" | head -c -4)
                
                # Save response for analysis
                mkdir -p /tmp/sqlmap_attack
                echo "$response_body" > "/tmp/sqlmap_attack/payload_${payload_count}_output.json"
                
                # Check for SQL injection indicators in response
                injection_found=false
                if echo "$response_body" | grep -q "error\|exception\|sql\|mysql\|postgresql"; then
                    injection_found=true
                fi
                if [ "$http_code" = "500" ]; then
                    injection_found=true
                fi
                
                if [ "$injection_found" = true ]; then
                    success_count=$((success_count + 1))
                    echo "  [SUCCESS] SQL injection indicators found (HTTP $http_code)"
                    echo "  [JSON_OUTPUT] /tmp/sqlmap_attack/payload_${payload_count}_output.json"
                else
                    failed_count=$((failed_count + 1))
                    echo "  [FAILED] No SQL injection detected (HTTP $http_code)"
                fi
                ;;
                
            "xss")
                echo "  [REAL ATTACK] Using XSS payload testing..."
                # Test XSS with real payload from attacks.txt
                response=$(curl -s -w "%{http_code}" \
                    -X "$method" \
                    -H "User-Agent: attacker" \
                    -H "X-Forwarded-For: 192.168.1.100" \
                    -H "X-Real-IP: 192.168.1.100" \
                    "$target$path?$data")
                
                http_code=$(echo "$response" | tail -c 4)
                # XSS success: 200 (payload accepted) or 500 (server error due to XSS)
                if [[ "$http_code" == "200" || "$http_code" == "500" ]]; then
                    success_count=$((success_count + 1))
                    echo "  [SUCCESS] XSS payload sent successfully (HTTP $http_code)"
                else
                    failed_count=$((failed_count + 1))
                    echo "  [FAILED] XSS attack failed with HTTP $http_code"
                fi
                ;;
                
            "traversal")
                echo "  [REAL ATTACK] Using directory traversal testing..."
                # Test directory traversal with curl
                response=$(curl -s -w "%{http_code}" \
                    -X "$method" \
                    -H "User-Agent: attacker" \
                    "$target$path")
                
                http_code=$(echo "$response" | tail -c 4)
                # Directory traversal success: 200 (file found) or 500 (server error due to traversal)
                if [[ "$http_code" == "200" || "$http_code" == "500" ]]; then
                    success_count=$((success_count + 1))
                    echo "  [SUCCESS] Directory traversal attempted (HTTP $http_code)"
                else
                    failed_count=$((failed_count + 1))
                    echo "  [FAILED] Directory traversal failed with HTTP $http_code"
                fi
                ;;
                
            "cmd_injection")
                echo "  [REAL ATTACK] Using command injection testing..."
                # Test command injection with payload from attacks.txt
                response=$(curl -s -w "%{http_code}" \
                    -X "$method" \
                    -H "User-Agent: attacker" \
                    -H "Content-Type: application/json" \
                    -d "$data" \
                    "$target$path")
                
                http_code=$(echo "$response" | tail -c 4)
                # Command injection success: 401 (auth failed), 500 (server error), or 200 (payload accepted)
                if [[ "$http_code" == "200" || "$http_code" == "401" || "$http_code" == "500" ]]; then
                    success_count=$((success_count + 1))
                    echo "  [SUCCESS] Command injection payload sent (HTTP $http_code)"
                else
                    failed_count=$((failed_count + 1))
                    echo "  [FAILED] Command injection failed with HTTP $http_code"
                fi
                ;;
                
            "auth_bypass")
                echo "  [REAL ATTACK] Using authentication bypass testing..."
                # Test with payload from attacks.txt
                response=$(curl -s -w "%{http_code}" \
                    -X "$method" \
                    -H "User-Agent: attacker" \
                    -H "Content-Type: application/json" \
                    -d "$data" \
                    "$target$path")
                
                http_code=$(echo "$response" | tail -c 4)
                # Auth bypass success: 200 (login successful) or 401 (auth failed - expected for test)
                if [[ "$http_code" == "200" || "$http_code" == "401" ]]; then
                    success_count=$((success_count + 1))
                    echo "  [SUCCESS] Authentication bypass attempted (HTTP $http_code)"
                else
                    failed_count=$((failed_count + 1))
                    echo "  [FAILED] Authentication bypass failed with HTTP $http_code"
                fi
                ;;
                
            "file_discovery")
                echo "  [REAL ATTACK] Using file discovery testing..."
                # Test file discovery based on attacks.txt path
                response=$(curl -s -w "%{http_code}" \
                    -X "$method" \
                    -H "User-Agent: attacker" \
                    "$target$path")
                
                http_code=$(echo "$response" | tail -c 4)
                # File discovery: 200 (file found), 403 (forbidden), or 404 (not found - expected for test)
                if [[ "$http_code" == "200" || "$http_code" == "403" || "$http_code" == "404" ]]; then
                    success_count=$((success_count + 1))
                    echo "  [SUCCESS] File discovery attempted (HTTP $http_code)"
                else
                    failed_count=$((failed_count + 1))
                    echo "  [FAILED] File discovery failed with HTTP $http_code"
                fi
                ;;
                
            "method_enum")
                echo "  [REAL ATTACK] Using HTTP method enumeration..."
                # Test HTTP method from attacks.txt
                response=$(curl -s -w "%{http_code}" \
                    -X "$method" \
                    -H "User-Agent: attacker" \
                    "$target$path")
                
                http_code=$(echo "$response" | tail -c 4)
                # HTTP method enumeration: 200 (allowed), 405 (method not allowed), or other responses
                if [[ "$http_code" == "200" || "$http_code" == "405" ]]; then
                    success_count=$((success_count + 1))
                    echo "  [SUCCESS] HTTP method $method tested (HTTP $http_code)"
                else
                    failed_count=$((failed_count + 1))
                    echo "  [FAILED] HTTP method $method failed (HTTP $http_code)"
                fi
                ;;
                
            *)
                echo "[WARNING] Unknown attack type: $attack_type"
                continue
                ;;
        esac
        
        executed_count=$((executed_count + 1))
        
        # Add attack end marker for structured parsing
        echo "===ATTACK_END==="
        echo "PAYLOAD_ID: $payload_count"
        # Determine result based on attack type
        if [ "$attack_type" = "sql_injection" ]; then
            echo "RESULT: $([ "$injection_found" = true ] && echo "SUCCESS" || echo "FAILED")"
        else
            echo "RESULT: $([ "$http_code" = "200" ] || [ "$http_code" = "500" ] || [ "$http_code" = "401" ] && echo "SUCCESS" || echo "FAILED")"
        fi
        echo "HTTP_CODE: $http_code"
        echo "TIMESTAMP: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "===ATTACK_END==="
        
        # Small delay between attacks
        sleep 1
        
    done < "$attack_file"
    
    echo "[DONE] Executed $executed_count attacks from file at $(date)"
    echo "[*] Success: $success_count, Failed: $failed_count"
    echo "[*] Attack file execution completed"
}

# Parse command line arguments
TARGET="http://fancystore.com"  # Default target
START_LINE=""
END_LINE=""
ATTACK_FILE="/opt/scripts/attacks.txt"  # Correct path - attack_scripts directory is mounted to /opt/scripts/

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
      echo "  $0 --target http://fancystore.com"
      echo "  $0 --start 3 --end 6"
      echo "  $0 --start 10 --end 15 --attack-file /opt/scripts/attacks.txt"
      exit 0
      ;;
    *)
      echo "Unknown option $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

echo "[*] Attacking target: $TARGET"
echo "[*] Attack file: $ATTACK_FILE"
if [[ -n "$START_LINE" && -n "$END_LINE" ]]; then
    echo "[*] Executing attacks from line $START_LINE to $END_LINE"
else
    echo "[*] Executing all attacks (no line range specified)"
fi
echo "Setting up environment variables..."

# Extract hostname and port from target URL
TARGET_HOST=$(echo $TARGET | sed 's|http://||' | sed 's|https://||' | cut -d':' -f1)
TARGET_PORT=$(echo $TARGET | sed 's|http://||' | sed 's|https://||' | cut -d':' -f2)
if [ -z "$TARGET_PORT" ] || [ "$TARGET_PORT" = "$TARGET_HOST" ]; then
    TARGET_PORT="80"
fi

# Set environment variables for the attack script
export TARGET_HOST="$TARGET_HOST"
export TARGET_PORT="$TARGET_PORT"
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

# ========================================
# COMPREHENSIVE ATTACK EXECUTION
# ========================================

echo "[*] ========================================"
echo "[*] COMPREHENSIVE ATTACK EXECUTION"
echo "[*] ========================================"

# Execute attacks from attack file
if [[ -f "$ATTACK_FILE" ]]; then
    echo "[*] Executing attacks from attack file..."
    execute_attacks_from_file "$ATTACK_FILE" "$START_LINE" "$END_LINE" "$TARGET"
    echo "[*] Attack file execution completed"
else
    echo "[ERROR] Attack file not found: $ATTACK_FILE"
    echo "[*] Available files in /opt/scripts/:"
    ls -la /opt/scripts/
    echo "[*] Available files in /opt/scripts/attack_scripts/:"
    ls -la /opt/scripts/attack_scripts/
    exit 1
fi

echo "[*] ========================================"
echo "[*] ATTACK EXECUTION COMPLETED"
echo "[*] ========================================"
echo "[*] All attacks have been executed successfully"
echo "[*] Check /log/attack.log for detailed results"


