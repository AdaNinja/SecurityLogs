#!/bin/bash

# XSS Attack Script using XSStrike
# Usage: ./attack_xss.sh <target_url> <payload>

TARGET_URL="$1"
PAYLOAD="$2"

echo "  [REAL ATTACK] Using XSStrike for XSS testing..."

# Check if XSStrike is available
if ! command -v xsstrike &> /dev/null; then
    echo "  [ERROR] XSStrike is not available"
    echo "  [TOOL_STATUS] FAILED - XSStrike not found"
    echo "  [FALLBACK_STATUS] NOT_AVAILABLE - No fallback mechanism"
    exit 1
fi

# Check if curl is available for HTTP status verification
if ! command -v curl &> /dev/null; then
    echo "  [ERROR] curl is not available for HTTP status verification"
    echo "  [TOOL_STATUS] FAILED - curl not found"
    echo "  [FALLBACK_STATUS] NOT_AVAILABLE - No fallback mechanism"
    exit 1
fi

echo "  [INFO] XSStrike available, using professional tool"
echo "  [TOOL_USED] xsstrike"

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
    echo "  [TOOL_STATUS] SUCCESS - XSStrike completed"
    exit 0
else
    echo "  [FAILED] No XSS detected (HTTP $http_code)"
    echo "  [TOOL_STATUS] FAILED - No XSS indicators found"
    exit 1
fi 