#!/bin/bash
# Basic Environment Setup Hook

echo "$(date): Setting up basic environment for scenario: $scenario_name"
echo "$(date): Scenario duration: $duration seconds"

# Create necessary directories
mkdir -p /logs
mkdir -p /data

# Set up environment variables
export SCENARIO_NAME="$scenario_name"
export SCENARIO_DURATION="$duration"

# Handle container information if available
if [ ! -z "$CONTAINERS" ]; then
    echo "$(date): Container information available"
    # Parse JSON container info if needed
    echo "$CONTAINERS" | python3 -c "
import json, sys
try:
    containers = json.load(sys.stdin)
    for name, info in containers.items():
        print(f'Container {name}: {info.get(\"id\", \"unknown\")}')
except:
    print('Could not parse container information')
" 2>/dev/null || echo "Container info parsing failed"
else
    echo "$(date): No container information available"
fi

echo "$(date): Basic environment setup completed" 