#!/bin/bash

# Reconnaissance script for attacker container
set -e

echo "[$(date)] Starting reconnaissance phase..."

# Set target information
TARGET_HOST=${TARGET_HOST:-victim-web}
TARGET_PORT=${TARGET_PORT:-80}
TARGET_URL=${TARGET_URL:-http://victim-web/login.php}

echo "[$(date)] Target: $TARGET_HOST:$TARGET_PORT"
echo "[$(date)] Target URL: $TARGET_URL"

# Wait for target to be available
echo "[$(date)] Waiting for target to be available..."
while ! curl -s "$TARGET_URL" > /dev/null 2>&1; do
    echo "[$(date)] Target not ready, waiting..."
    sleep 5
done
echo "[$(date)] Target is available!"

# Basic port scan
echo "[$(date)] Running port scan..."
nmap -sS -p- $TARGET_HOST > /opt/output/nmap_scan.txt 2>&1

# Web application enumeration
echo "[$(date)] Running web application enumeration..."
nikto -h $TARGET_HOST > /opt/output/nikto_scan.txt 2>&1

# Directory enumeration
echo "[$(date)] Running directory enumeration..."
dirb http://$TARGET_HOST/ /usr/share/dirb/wordlists/common.txt > /opt/output/dirb_scan.txt 2>&1

# Check for common vulnerabilities
echo "[$(date)] Checking for common vulnerabilities..."
curl -s "$TARGET_URL" | grep -i "error\|sql\|mysql\|database" > /opt/output/vuln_check.txt 2>&1

echo "[$(date)] Reconnaissance completed!"
echo "[$(date)] Results saved to /opt/output/"

# Keep script running for interactive use
tail -f /dev/null 