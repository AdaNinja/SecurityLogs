#!/bin/bash

# HTTP Method Enumeration Attack Script using Nmap
# Usage: ./attack_method_enum.sh <target_url> <payload>

TARGET_URL="$1"
PAYLOAD="$2"

echo "  [REAL ATTACK] Using Nmap for HTTP method enumeration testing..."

# Extract host from URL
TARGET_HOST=$(echo "$TARGET_URL" | sed 's|^https*://||' | sed 's|/.*$||')

# Install Nmap if not available
if ! command -v nmap &> /dev/null; then
    echo "  [INFO] Installing Nmap..."
    apt-get update && apt-get install -y nmap || {
        echo "  [WARNING] Failed to install Nmap, using curl fallback"
        # Fallback to curl-based method testing
        for method in PUT DELETE HEAD OPTIONS TRACE PATCH; do
            response=$(curl -s -w "%{http_code}" \
                -X "$method" \
                -H "User-Agent: attacker" \
                --max-time 10 \
                "$TARGET_URL")
            
            http_code=$(echo "$response" | tail -c 4)
            
            if [[ "$http_code" != "405" && "$http_code" != "501" ]]; then
                echo "  [SUCCESS] HTTP method $method allowed (HTTP $http_code)"
                exit 0
            fi
        done
        
        echo "  [FAILED] No unusual HTTP methods found"
        exit 1
    }
fi

# Run Nmap HTTP methods script
echo "  [INFO] Running Nmap against: $TARGET_HOST"
nmap_output=$(timeout 30 nmap \
    -p 80 \
    --script http-methods \
    --script-args http-methods.url-path=/ \
    "$TARGET_HOST" \
    2>&1)

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
    "$TARGET_URL")

http_code=$(echo "$curl_response" | tail -c 4)

# Save Nmap output
echo "$nmap_output" > "/tmp/nmap_output.txt"

# Determine success
if [ "$method_found" = true ] || [ "$http_code" != "405" ]; then
    echo "  [SUCCESS] Unusual HTTP methods detected by Nmap (HTTP $http_code)"
    echo "  [TOOL_OUTPUT] /tmp/nmap_output.txt"
    exit 0
else
    echo "  [FAILED] No unusual HTTP methods detected (HTTP $http_code)"
    exit 1
fi 