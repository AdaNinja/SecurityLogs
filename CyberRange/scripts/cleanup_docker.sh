#!/bin/bash

# Docker Cleanup Script for CyberRange
# Removes unnecessary Docker images and containers to save space

echo "🧹 CyberRange Docker Cleanup"
echo "=============================="

# Required images for CyberRange
REQUIRED_IMAGES=(
    "nginx:alpine"
    "python:3.9-slim" 
    "bkimminich/juice-shop:latest"
    "ras-attacker:latest"
)

echo "📋 Required images for CyberRange:"
for image in "${REQUIRED_IMAGES[@]}"; do
    echo "  ✓ $image"
done

echo ""
echo "🔍 Current Docker images related to CyberRange:"
docker images | grep -E "(nginx|python|juice|attacker)" || echo "  No related images found"

echo ""
read -p "🤔 Do you want to remove unused Docker containers and images? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "🗑️  Cleaning up Docker containers..."
    
    # Stop and remove all containers
    if [ "$(docker ps -aq)" ]; then
        echo "  Stopping all containers..."
        docker stop $(docker ps -aq) 2>/dev/null || true
        echo "  Removing all containers..."
        docker rm $(docker ps -aq) 2>/dev/null || true
    else
        echo "  No containers to clean up"
    fi
    
    echo ""
    echo "🗑️  Cleaning up Docker images..."
    
    # Remove dangling images
    echo "  Removing dangling images..."
    docker image prune -f
    
    # Clean up build cache
    echo "  Cleaning build cache..."
    docker builder prune -f
    
    # Clean up volumes
    echo "  Cleaning unused volumes..."
    docker volume prune -f
    
    # Clean up networks
    echo "  Cleaning unused networks..."
    docker network prune -f
    
    echo ""
    echo "✅ Docker cleanup completed!"
    
    echo ""
    echo "📊 Remaining images:"
    docker images | grep -E "(nginx|python|juice|attacker)" || echo "  No related images found"
    
else
    echo "❌ Cleanup cancelled"
fi

echo ""
echo "💡 Tips:"
echo "  - Run 'docker system df' to see disk usage"
echo "  - Run 'docker system prune -a' for deep cleaning (removes all unused images)"
echo "  - Required images will be automatically pulled/built when running scenarios"
