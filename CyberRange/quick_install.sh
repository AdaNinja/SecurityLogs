#!/bin/bash
#
# Quick Install Script for School Environment
# Handles externally-managed-environment restrictions
#

echo "🚀 CyberRange Quick Install for School Environment"
echo "=================================================="

# Method 1: Try user installation (safest)
echo "📦 Method 1: Installing to user directory..."
if pip3 install --user -r requirements-minimal.txt; then
    echo "✅ Installation successful!"
    echo ""
    echo "🎯 You can now run:"
    echo "   python3 run_scenario.py --config scenarios/test_multi_nodes.yaml"
    exit 0
fi

echo "❌ User installation failed. Trying alternative..."

# Method 2: Try with --break-system-packages (risky but works)
echo "📦 Method 2: Installing with --break-system-packages..."
if pip3 install --break-system-packages -r requirements-minimal.txt; then
    echo "✅ Installation successful!"
    echo ""
    echo "🎯 You can now run:"
    echo "   python3 run_scenario.py --config scenarios/test_multi_nodes.yaml"
    exit 0
fi

echo "❌ All installation methods failed."
echo ""
echo "🔧 Manual installation options:"
echo "1. Install system packages:"
echo "   sudo apt install python3-docker python3-yaml python3-pandas python3-requests"
echo ""
echo "2. Use pipx (if available):"
echo "   pipx install docker"
echo ""
echo "3. Contact system administrator for help"
