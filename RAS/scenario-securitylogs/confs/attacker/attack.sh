#!/bin/bash

# Parse command line arguments
TARGET="http://fancystore.com"  # Default target

while [[ $# -gt 0 ]]; do
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

echo "Attacking target: $TARGET"
echo "Installing required tools..."

# Install required packages (removed git to avoid network issues)
apt-get update
apt-get install -y python3 python3-pip curl wget python3-requests python3-dnspython nmap

echo "Setting up environment variables..."

# Extract hostname and port from target URL
TARGET_HOST=$(echo $TARGET | sed 's|http://||' | sed 's|https://||' | cut -d':' -f1)
TARGET_PORT=$(echo $TARGET | sed 's|http://||' | sed 's|https://||' | cut -d':' -f2)
if [ -z "$TARGET_PORT" ] || [ "$TARGET_PORT" = "$TARGET_HOST" ]; then
    TARGET_PORT="80"
fi

# Set environment variables
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

echo "Starting SecurityLogs attack script..."
echo "Sleeping for 30 seconds before starting the attack..."
sleep 30

# Run our SecurityLogs attack script
python3 /opt/scripts/container_attack.py --variant-id moderate


