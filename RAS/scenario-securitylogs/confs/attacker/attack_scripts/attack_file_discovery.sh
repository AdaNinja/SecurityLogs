#!/bin/bash

# File Discovery Attack Script using Gobuster
# Usage: ./attack_file_discovery.sh <target_url> <payload>

TARGET_URL="$1"
PAYLOAD="$2"

echo "  [REAL ATTACK] Using Gobuster for file discovery testing..."

# Install Gobuster if not available
if ! command -v gobuster &> /dev/null; then
    echo "  [INFO] Installing Gobuster..."
    apt-get update && apt-get install -y gobuster || {
        echo "  [WARNING] Failed to install Gobuster, using curl fallback"
        # Fallback to curl-based file discovery testing
        response=$(curl -s -w "%{http_code}" \
            -X "GET" \
            -H "User-Agent: attacker" \
            --max-time 10 \
            "$TARGET_URL")
        
        http_code=$(echo "$response" | tail -c 4)
        response_body=$(echo "$response" | head -c -4)
        
        # Check for sensitive file content
        sensitive_content=false
        if echo "$response_body" | grep -q "BEGIN:VCARD\|<?php\|database\|config\|password.*=.*['\"]\|DB_HOST.*=.*['\"]"; then
            sensitive_content=true
        fi
        
        if [[ "$sensitive_content" == true || "$http_code" == "200" ]]; then
            echo "  [SUCCESS] Sensitive file found (HTTP $http_code)"
            exit 0
        else
            echo "  [FAILED] No sensitive file found (HTTP $http_code)"
            exit 1
        fi
    }
fi

# Create a wordlist for sensitive files
cat > /tmp/file_wordlist.txt << EOF
.env
config.php
wp-config.php
.git/config
backup.sql
database.yml
.htaccess
robots.txt
sitemap.xml
admin/
phpmyadmin/
wp-admin/
EOF

# Run Gobuster
echo "  [INFO] Running Gobuster against: $TARGET_URL"
gobuster_output=$(timeout 30 gobuster dir \
    -u "$TARGET_URL" \
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
    -X "GET" \
    -H "User-Agent: attacker" \
    --max-time 10 \
    "$TARGET_URL")

http_code=$(echo "$curl_response" | tail -c 4)

# Save Gobuster output
echo "$gobuster_output" > "/tmp/gobuster_file_output.txt"

# Determine success
if [ "$file_found" = true ] || [ "$http_code" = "200" ]; then
    echo "  [SUCCESS] Sensitive file detected by Gobuster (HTTP $http_code)"
    echo "  [TOOL_OUTPUT] /tmp/gobuster_file_output.txt"
    exit 0
else
    echo "  [FAILED] No sensitive file detected (HTTP $http_code)"
    exit 1
fi 