#!/bin/bash

# CyberRange Scenario Testing Script
# Tests all three scenarios to ensure they work correctly

echo "================================"
echo "CyberRange Scenario Test Runner"
echo "================================"

# Function to test a scenario
test_scenario() {
    local scenario_file="$1"
    local scenario_name="$2"
    local duration="$3"
    
    echo ""
    echo "Testing: $scenario_name"
    echo "File: $scenario_file"
    echo "Duration: $duration seconds"
    echo "----------------------------"
    
    # Validate YAML syntax
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "import yaml; yaml.safe_load(open('$scenario_file'))" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "✅ YAML syntax: Valid"
        else
            echo "❌ YAML syntax: Invalid"
            return 1
        fi
    fi
    
    # Check if required scripts exist
    if [ -f "scenario-securitylogs/confs/attacker/unified_attack.sh" ]; then
        echo "✅ Attack script: Found"
    else
        echo "❌ Attack script: Not found"
        return 1
    fi
    
    if [ -f "scenario-securitylogs/confs/user/benign.sh" ]; then
        echo "✅ Benign script: Found"
    else
        echo "❌ Benign script: Not found"
        return 1
    fi
    
    # Simulate running the scenario (dry run)
    echo "🔍 Dry run: Checking scenario configuration..."
    
    # Extract key information
    attack_types=$(grep -A10 "attack_types:" "$scenario_file" | head -2 | tail -1)
    duration_config=$(grep "duration:" "$scenario_file" | head -1)
    
    echo "   Attack types: $attack_types"
    echo "   Duration: $duration_config"
    
    echo "✅ Scenario test passed"
    return 0
}

# Main execution
cd /home/jiayi/SecurityLogs/CyberRange

echo ""
echo "1. Testing 'Test All Features' scenario..."
test_scenario "scenarios/test_all_features.yaml" "Test All Features" "600"

echo ""
echo "2. Testing 'Realistic Production' scenario..."
test_scenario "scenarios/realistic_production.yaml" "Realistic Production (1.3% attack)" "7200"

echo ""
echo "3. Testing 'Balanced ML Dataset' scenario..."  
test_scenario "scenarios/balanced_ml_dataset.yaml" "Balanced ML Dataset (7 classes)" "3600"

echo ""
echo "4. Testing 'Advanced Four-Phase Attack' scenario..."
test_scenario "scenarios/advanced_attack_four_phase.yaml" "Advanced Attack with Lateral Movement" "180"

echo ""
echo "================================"
echo "Summary"
echo "================================"

# Count payload files
payload_count=$(ls -1 scenario-securitylogs/confs/attacker/attacks/*.txt 2>/dev/null | wc -l)
echo "📁 Attack payload files: $payload_count"

# List payload files
echo "📄 Available payloads:"
for file in scenario-securitylogs/confs/attacker/attacks/*.txt; do
    if [ -f "$file" ]; then
        basename "$file"
    fi
done

echo ""
echo "🚀 Ready to run scenarios with:"
echo "   python3 run_scenario.py --config scenarios/<scenario_file>.yaml"
echo ""
echo "Example commands:"
echo "   python3 run_scenario.py --config scenarios/test_all_features.yaml"
echo "   python3 run_scenario.py --config scenarios/realistic_production.yaml"
echo "   python3 run_scenario.py --config scenarios/balanced_ml_dataset.yaml"
echo "   python3 run_scenario.py --config scenarios/advanced_attack_four_phase.yaml"

echo ""
echo "✅ All scenario tests completed!"
