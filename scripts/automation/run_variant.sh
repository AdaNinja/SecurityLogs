#!/bin/bash

# Low and Slow SQL Injection Variant Runner
# Usage: ./run_variant.sh <variant_id>

set -e

VARIANT_ID=${1:-"lowscan_stealthy"}
EXPERIMENT_DIR="experiments"
DATA_DIR="data"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Load variant configuration
if [ ! -f "$EXPERIMENT_DIR/variants.yml" ]; then
    echo "Error: variants.yml not found"
    exit 1
fi

# Function to extract YAML values (simplified)
get_variant_config() {
    local variant_id=$1
    local key=$2
    # This is a simplified YAML parser - in production use proper YAML tools
    grep -A 20 "variants:" "$EXPERIMENT_DIR/variants.yml" | grep -A 20 "$variant_id:" | grep "$key:" | head -1 | cut -d: -f2 | tr -d ' '
}

# Extract variant configuration
WEBAPP_PORT=$(get_variant_config $VARIANT_ID "webapp")
ATTACKER_PORT=$(get_variant_config $VARIANT_ID "attacker")
NETWORK_NAME=$(get_variant_config $VARIANT_ID "network")
VARIANT_ID_CONFIG=$(get_variant_config $VARIANT_ID "variant_id")

# Set environment variables
export VARIANT_ID=$VARIANT_ID
export WEBAPP_PORT=${WEBAPP_PORT:-8080}
export ATTACKER_PORT=${ATTACKER_PORT:-8081}
export NETWORK_NAME=${NETWORK_NAME:-"${VARIANT_ID}_net"}
export EXPERIMENT_TIMESTAMP=$TIMESTAMP

echo "=== Starting Variant: $VARIANT_ID ==="
echo "Timestamp: $TIMESTAMP"
echo "Webapp Port: $WEBAPP_PORT"
echo "Attacker Port: $ATTACKER_PORT"
echo "Network: $NETWORK_NAME"

# Create variant-specific directories
VARIANT_DATA_DIR="$DATA_DIR/logs/$VARIANT_ID"
VARIANT_OUTPUT_DIR="$DATA_DIR/datasets"
mkdir -p "$VARIANT_DATA_DIR" "$VARIANT_OUTPUT_DIR"

# Function to cleanup on exit
cleanup() {
    echo "Cleaning up variant: $VARIANT_ID"
    cd scenarios/low-and-slow-sqli 2>/dev/null || cd ../../scenarios/low-and-slow-sqli 2>/dev/null || true
    docker-compose -p "$VARIANT_ID" down --volumes --remove-orphans 2>/dev/null || true
    echo "Cleanup completed for $VARIANT_ID"
}

# Set up signal handlers
trap cleanup EXIT SIGINT SIGTERM

# Step 1: Start containers with variant-specific configuration
echo "Step 1: Starting containers for variant $VARIANT_ID"
cd scenarios/low-and-slow-sqli

# Create variant-specific docker-compose override
cat > docker-compose.override.yml << EOF
version: '3.8'
services:
  webapp:
    ports:
      - "${WEBAPP_PORT}:80"
    environment:
      - VARIANT_ID=${VARIANT_ID}
      - EXPERIMENT_TIMESTAMP=${EXPERIMENT_TIMESTAMP}
    volumes:
      - ../../${VARIANT_DATA_DIR}:/var/log
      - ../../${VARIANT_DATA_DIR}/pcap:/data/raw
      - ../../${VARIANT_DATA_DIR}/output:/opt/output

  attacker:
    environment:
      - VARIANT_ID=${VARIANT_ID}
      - EXPERIMENT_TIMESTAMP=${EXPERIMENT_TIMESTAMP}
    volumes:
      - ../../${VARIANT_DATA_DIR}/output:/opt/output
      - ../../${VARIANT_DATA_DIR}/logs:/opt/logs

  tcpdump:
    environment:
      - VARIANT_ID=${VARIANT_ID}
      - EXPERIMENT_TIMESTAMP=${EXPERIMENT_TIMESTAMP}
    volumes:
      - ../../${VARIANT_DATA_DIR}/pcap:/pcaps
      - ../../${VARIANT_DATA_DIR}/logs:/logs

networks:
  attacknet:
    name: ${NETWORK_NAME}
EOF

# Start containers
docker-compose -p "$VARIANT_ID" up -d

# Step 2: Wait for containers to be ready
echo "Step 2: Waiting for containers to be ready..."
sleep 30

# Health check
echo "Checking container health..."
for container in "securitylogs-webapp" "securitylogs-attacker" "securitylogs-tcpdump"; do
    if ! docker ps | grep -q "$container"; then
        echo "Error: Container $container is not running"
        exit 1
    fi
done

echo "All containers are healthy"

# Step 3: Apply network conditions (optional - requires root)
echo "Step 3: Applying network conditions..."
cd ../../network 2>/dev/null || cd ../../network 2>/dev/null || true
if [ "$EUID" -eq 0 ]; then
    bash apply_netem.sh --delay 50 --loss 1 --jitter 10
    echo "Network conditions applied successfully"
else
    echo "Warning: Skipping network conditions (requires root/sudo)"
    echo "To apply network conditions manually, run: sudo bash apply_netem.sh --delay 50 --loss 1 --jitter 10"
fi
cd ../../experiments

# Step 4: Start benign traffic
echo "Step 4: Starting benign traffic simulation..."
echo "Note: Benign traffic simulation may not be available in all containers"
docker exec "securitylogs-webapp" bash /opt/scripts/benign_modules/run_benign.sh &
BENIGN_PID=$!
echo "Benign traffic started (PID: $BENIGN_PID)"

# Step 5: Run attack sequence
echo "Step 5: Running attack sequence..."
sleep 60  # Let benign traffic establish

# Run reconnaissance
echo "Running reconnaissance phase..."
echo "Note: Reconnaissance script may not be available, proceeding with attack phase..."

sleep 30

# Run SQL injection attacks
echo "Running SQL injection attacks..."
docker exec "securitylogs-attacker" python3 /opt/scripts/attack_modules/container_attack.py --risk 1 --level 2

sleep 30

# Step 6: Collect data
echo "Step 6: Collecting experiment data..."
sleep 30  # Allow logs to flush

# Ensure variant data directory exists
mkdir -p "$VARIANT_DATA_DIR"

# Collect container logs
for container in "securitylogs-webapp" "securitylogs-attacker" "securitylogs-tcpdump"; do
    echo "Collecting logs from $container"
    docker logs "$container" > "$VARIANT_DATA_DIR/${container}_logs.txt" 2>&1 || echo "Failed to collect logs from $container"
done

# Collect host logs
HOSTLOGS_DIR=$(pwd)
cd /home/jiayi/SecurityLogs
python3 data/collect_host_logs.py "$VARIANT_ID" || echo "Failed to collect host logs"
cd "$HOSTLOGS_DIR"

# Collect PCAP files
if [ -d "$VARIANT_DATA_DIR/pcap" ]; then
    echo "Collecting PCAP files..."
    cp "$VARIANT_DATA_DIR/pcap"/*.pcap "$VARIANT_DATA_DIR/" 2>/dev/null || true
fi

# Step 7: Run ETL and merge
echo "Step 7: Running ETL and data merging..."
ETL_DIR=$(pwd)
cd /home/jiayi/SecurityLogs

# Run ETL scripts with variant-specific data
python3 data/etl_container_logs.py || echo "ETL container logs failed"
python3 data/etl_application_logs.py || echo "ETL application logs failed"
python3 data/etl_attack_logs.py || echo "ETL attack logs failed"
python3 data/etl_host_logs.py || echo "ETL host logs failed"

# 修复日志权限
sudo chmod -R a+r data/logs/

# Create variant-specific merged dataset
python3 data/merge_variant_logs.py --variant-id "$VARIANT_ID" --input-dir "$VARIANT_DATA_DIR" --output-file "$VARIANT_OUTPUT_DIR/${VARIANT_ID}_dataset.jsonl" || echo "Merge failed"

cd "$ETL_DIR"

echo "=== Variant $VARIANT_ID completed successfully ==="
echo "Dataset saved to: $VARIANT_OUTPUT_DIR/${VARIANT_ID}_dataset.jsonl" 