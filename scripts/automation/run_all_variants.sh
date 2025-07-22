#!/bin/bash

# Run All Variants Script
# Automatically runs all variants defined in variants.yml

set -e

EXPERIMENT_DIR="scripts/automation"
DATA_DIR="data"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "=== Starting Multi-Variant Experiment ==="
echo "Timestamp: $TIMESTAMP"
echo "Experiment directory: $EXPERIMENT_DIR"
echo "Data directory: $DATA_DIR"

# Check if variants.yml exists
if [ ! -f "$EXPERIMENT_DIR/variants.yml" ]; then
    echo "Error: variants.yml not found"
    exit 1
fi

# Extract variant IDs from variants.yml
VARIANT_IDS=()
while IFS= read -r line; do
    if [[ $line =~ ^[[:space:]]*([a-zA-Z_][a-zA-Z0-9_]*): ]]; then
        variant_id="${BASH_REMATCH[1]}"
        if [[ "$variant_id" != "variants" && "$variant_id" != "experiment" ]]; then
            VARIANT_IDS+=("$variant_id")
        fi
    fi
done < "$EXPERIMENT_DIR/variants.yml"

echo "Found variants: ${VARIANT_IDS[*]}"

# Create experiment summary
SUMMARY_FILE="$DATA_DIR/experiment_summary_${TIMESTAMP}.md"
cat > "$SUMMARY_FILE" << EOF
# Multi-Variant Experiment Summary

**Experiment Timestamp:** $TIMESTAMP  
**Total Variants:** ${#VARIANT_IDS[@]}

## Variants Executed

EOF

# Run each variant
for variant_id in "${VARIANT_IDS[@]}"; do
    echo ""
    echo "=== Running Variant: $variant_id ==="
    
    # Create variant-specific log file
    VARIANT_LOG="$DATA_DIR/logs/${variant_id}_run_${TIMESTAMP}.log"
    mkdir -p "$(dirname "$VARIANT_LOG")"
    
    # Run variant with logging
    if bash ./run_variant.sh "$variant_id" 2>&1 | tee "$VARIANT_LOG"; then
        echo "✓ Variant $variant_id completed successfully"
        
        # Add to summary
        cat >> "$SUMMARY_FILE" << EOF
- **$variant_id**: ✅ Completed
  - Log: \`$VARIANT_LOG\`
  - Dataset: \`data/datasets/${variant_id}_dataset.jsonl\`

EOF
    else
        echo "✗ Variant $variant_id failed"
        
        # Add to summary
        cat >> "$SUMMARY_FILE" << EOF
- **$variant_id**: ❌ Failed
  - Log: \`$VARIANT_LOG\`

EOF
    fi
    
    # Wait between variants to avoid resource conflicts
    if [ "$variant_id" != "${VARIANT_IDS[-1]}" ]; then
        echo "Waiting 60 seconds before next variant..."
        sleep 60
    fi
done

# Generate final summary
cat >> "$SUMMARY_FILE" << EOF

## Experiment Results

### Datasets Generated
\`\`\`bash
# List all generated datasets
ls -la $DATA_DIR/datasets/*_dataset.jsonl
\`\`\`

### Statistics
\`\`\`bash
# View dataset statistics
ls -la $DATA_DIR/datasets/*_stats.json
\`\`\`

### Analysis Commands
\`\`\`bash
# Analyze all variants
python3 data/analyze_all_variants.py

# Compare variants
python3 data/compare_variants.py
\`\`\`

## Notes
- Each variant runs in isolated containers
- All logs are collected and converted to unified JSON Lines format
- Attack events are automatically labeled
- PCAP files are captured for network analysis
EOF

echo ""
echo "=== Multi-Variant Experiment Completed ==="
echo "Summary saved to: $SUMMARY_FILE"
echo "Datasets available in: $DATA_DIR/datasets/"
echo "Logs available in: $DATA_DIR/logs/"

# List generated datasets
echo ""
echo "Generated datasets:"
ls -la "$DATA_DIR/datasets/"*_dataset.jsonl 2>/dev/null || echo "No datasets found"

echo ""
echo "Experiment completed at: $(date)" 