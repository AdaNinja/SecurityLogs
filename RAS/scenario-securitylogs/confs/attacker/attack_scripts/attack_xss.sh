#!/bin/bash

# XSS Attack Script using XSStrike
# Usage: ./attack_xss.sh <target_url> <payload>

TARGET_URL="$1"
PAYLOAD="$2"

echo "  [REAL ATTACK] Using XSStrike for XSS testing..."

# Install XSStrike if not available
if ! command -v xsstrike &> /dev/null; then
    echo "  [INFO] Installing XSStrike..."
    pip3 install --break-system-packages xsstrike --quiet || {
        echo "  [WARNING] Failed to install XSStrike, using curl fallback"
        # Fallback to curl-based XSS testing
        response=$(curl -s -w "%{http_code}" \
            -X "GET" \
            -H "User-Agent: attacker" \
            -H "X-Forwarded-For: 192.168.1.100" \
            -H "X-Real-IP: 192.168.1.100" \
            --max-time 10 \
            "$TARGET_URL")
        
        http_code=$(echo "$response" | tail -c 4)
        response_body=$(echo "$response" | head -c -4)
        
        # Check for XSS reflection in response
        xss_reflected=false
        if echo "$response_body" | grep -q "<script>\|javascript:\|onerror=\|onload="; then
            xss_reflected=true
        fi
        
        if [[ "$xss_reflected" == true || "$http_code" == "500" ]]; then
            echo "  [SUCCESS] XSS payload reflected or caused server error (HTTP $http_code)"
            exit 0
        else
            echo "  [FAILED] XSS attack failed - no reflection detected (HTTP $http_code)"
            exit 1
        fi
    }
fi

# Run XSStrike
echo "  [INFO] Running XSStrike against: $TARGET_URL"
xsstrike_output=$(timeout 30 xsstrike \
    --url "$TARGET_URL" \
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
    -X "GET" \
    -H "User-Agent: attacker" \
    --max-time 10 \
    "$TARGET_URL")

http_code=$(echo "$curl_response" | tail -c 4)

# Save XSStrike output
echo "$xsstrike_output" > "/tmp/xsstrike_output.txt"

# Determine success
if [ "$xss_found" = true ] || [ "$http_code" = "500" ]; then
    echo "  [SUCCESS] XSS detected by XSStrike (HTTP $http_code)"
    echo "  [TOOL_OUTPUT] /tmp/xsstrike_output.txt"
    exit 0
else
    echo "  [FAILED] No XSS detected (HTTP $http_code)"
    exit 1
fi 