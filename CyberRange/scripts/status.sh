#!/bin/bash
# Status script - Check system status

echo "🔍 CyberRange System Status"
echo "=========================="

# Check containers
echo "📦 Containers:"
docker ps --filter "name=juice-shop|nginx|attacker|benign_user" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Check logs
echo -e "\n📄 Logs:"
ls -la logs/ 2>/dev/null || echo "No logs directory"

# Check data
echo -e "\n📊 Data:"
ls -la data/raw/ 2>/dev/null | head -5 || echo "No data directory"

# Check output
echo -e "\n📤 Output:"
ls -la output/ 2>/dev/null || echo "No output directory" 