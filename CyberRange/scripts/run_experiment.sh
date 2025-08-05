#!/bin/bash
# Run experiment script - Complete automation workflow

if [ $# -eq 0 ]; then
    echo "Usage: $0 <config_file>"
    echo "Example: $0 scenarios/modular_demo_detailed.yaml"
    exit 1
fi

CONFIG_FILE=$1

echo "🚀 Starting CyberRange experiment with config: $CONFIG_FILE"

# Step 1: Clean
echo "📋 Step 1: Cleaning environment..."
./scripts/clean.sh

# Step 2: Run experiment
echo "📋 Step 2: Running experiment..."
python3 run_scenario.py --config $CONFIG_FILE

# Step 3: Parse data
echo "📋 Step 3: Parsing data..."
python3 parsers/parse_logs.py --input-dir logs --output-dir output --log-type all

echo "🎉 Experiment completed! Check output/ directory for results." 