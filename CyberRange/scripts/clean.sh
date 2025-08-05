#!/bin/bash
# Clean script - Clear logs, data and containers

echo "🧹 Cleaning CyberRange environment..."

# Stop and remove containers
docker stop $(docker ps -q --filter "name=juice-shop|nginx|attacker|benign_user") 2>/dev/null || true
docker rm $(docker ps -aq --filter "name=juice-shop|nginx|attacker|benign_user") 2>/dev/null || true

# Remove networks
docker network rm internal-net external-net 2>/dev/null || true

# Clear logs completely
rm -rf logs/* 2>/dev/null || true
rm -rf logs/.* 2>/dev/null || true
mkdir -p logs/nginx logs/attacker logs/benign_user

# Clear data
rm -rf data/raw/* 2>/dev/null || true
rm -rf output/* 2>/dev/null || true

# Clear pcap files
find . -name "*.pcap" -delete 2>/dev/null || true

# Clear any remaining CSV files in logs directory
find logs/ -name "*.csv" -delete 2>/dev/null || true

echo "✅ Cleanup completed" 