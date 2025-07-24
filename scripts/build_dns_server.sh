#!/bin/bash
# Build DNS Server Container - Host Network for Build, Isolated Network for Runtime

echo "🔨 Building DNS Server Container..."

echo "📦 Build Phase: Using host network for fast package download..."
# Build DNS server image with host network (for package installation only)
docker build --network=host -t securitylogs-dns-server:latest ../../containers/dns-server/

if [ $? -eq 0 ]; then
    echo "✅ DNS Server container built successfully!"
    echo ""
    echo "🔒 Runtime Configuration:"
    echo "   - DNS Server will run in isolated container network"
    echo "   - No host port mapping (maintains network isolation)"
    echo "   - Accessible only from other containers via 'dns-server' hostname"
    echo ""
    echo "🌐 Network Architecture:"
    echo "   Build Time:  Host Network (fast downloads)"
    echo "   Runtime:     Isolated Container Network (security)"
    echo ""
    echo "🚀 To start the DNS server:"
    echo "   docker-compose up dns-server"
    echo ""
    echo "🔍 DNS server will be accessible from other containers via:"
    echo "   dns-server (container hostname)"
    echo ""
    echo "✅ Network isolation maintained for experiments!"
else
    echo "❌ Failed to build DNS server container"
    exit 1
fi 