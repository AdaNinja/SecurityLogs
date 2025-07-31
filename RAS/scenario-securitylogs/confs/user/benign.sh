#!/bin/sh

# Redirect all output to log file
exec > >(tee /log/user/user.log) 2>&1

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

echo "Making benign requests to target: $TARGET"
echo "Installing curl..."
apk add --no-cache curl

# Get container IP for log correlation
CONTAINER_IP=$(hostname -i | awk '{print $1}')
echo "[INFO] Container IP: $CONTAINER_IP"

echo "Sleeping for 10 seconds before starting the benign requests..."
sleep 10

for i in $(seq 1 50); do
  echo "Running benign iteration $i"
  # Simulate a benign request by sending a request to the target
  TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
  curl -X GET "$TARGET" \
    -H "User-Agent: Mozilla/5.0 (compatible; BenignBot/1.0)" \
    -H "X-Timestamp: $TIMESTAMP" \
    -H "X-Source-IP: $CONTAINER_IP" \
    -H "X-Traffic-Type: benign"
  sleep 2
done

echo "Benign traffic completed" 