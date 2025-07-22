#!/bin/bash

# Debug Container Logs Script
# Helps diagnose why container logs are empty

set -e

echo "=== Container Logs Debug Script ==="
echo "Timestamp: $(date)"
echo ""

# Check if we're in the right directory
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ docker-compose.yml not found. Please run from scenarios/low-and-slow-sqli/"
    exit 1
fi

echo "1. Checking Docker Compose Status"
echo "================================"
docker-compose ps
echo ""

echo "2. Checking Container Images"
echo "==========================="
docker images | grep securitylogs || echo "No securitylogs images found"
echo ""

echo "3. Checking Container Logs (if containers exist)"
echo "=============================================="

# Check each container
for container in "securitylogs-webapp" "securitylogs-attacker" "securitylogs-tcpdump" "securitylogs-log-aggregator"; do
    echo "--- $container ---"
    if docker ps -a | grep -q "$container"; then
        echo "Container exists:"
        docker ps -a | grep "$container"
        echo ""
        echo "Container logs:"
        docker logs "$container" 2>&1 | head -20
        echo ""
        echo "Log line count: $(docker logs "$container" 2>&1 | wc -l)"
    else
        echo "❌ Container does not exist"
    fi
    echo ""
done

echo "4. Checking Experiment Data Directory"
echo "==================================="
if [ -d "../../experiments/data/logs" ]; then
    echo "Experiment logs directory exists:"
    ls -la ../../experiments/data/logs/
    echo ""
    
    for variant in "lowscan_stealthy" "lowscan_moderate" "lowscan_aggressive"; do
        if [ -d "../../experiments/data/logs/$variant" ]; then
            echo "--- $variant ---"
            ls -la "../../experiments/data/logs/$variant/"
            echo ""
            
            # Check attacker logs specifically
            attacker_log_file="../../experiments/data/logs/$variant/securitylogs-attacker_logs.txt"
            if [ -f "$attacker_log_file" ]; then
                echo "Attacker log file size: $(wc -c < "$attacker_log_file") bytes"
                echo "Attacker log file lines: $(wc -l < "$attacker_log_file")"
                echo "First 5 lines:"
                head -5 "$attacker_log_file"
            else
                echo "❌ Attacker log file not found"
            fi
            echo ""
        fi
    done
else
    echo "❌ Experiment logs directory not found"
fi

echo "5. Checking Attack Script Execution"
echo "================================="

# Check if attack scripts exist
echo "Attack script locations:"
find . -name "*attack*" -type f | head -10
echo ""

# Check if attack output directory exists
if [ -d "../../data/output" ]; then
    echo "Output directory contents:"
    ls -la ../../data/output/
else
    echo "❌ Output directory not found"
fi

echo "6. Recommendations"
echo "================="
echo "If containers are not running:"
echo "1. Run: docker-compose up -d"
echo "2. Wait for containers to start"
echo "3. Run: docker-compose logs"
echo ""
echo "If containers are running but logs are empty:"
echo "1. Check if attack scripts are being executed"
echo "2. Verify container command is not just 'tail -f /dev/null'"
echo "3. Check if attack scripts have proper logging"
echo ""
echo "If experiment data is missing:"
echo "1. Run the experiment script again"
echo "2. Check if data collection script is working"
echo "3. Verify file permissions and paths"

echo ""
echo "=== Debug Complete ===" 