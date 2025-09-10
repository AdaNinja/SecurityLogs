# Suricata Validation Guide

## 🎯 Quick Start

### Prerequisites
- Group A experiments completed (baseline without Suricata)
- Suricata scenario configuration ready
- Python dependencies installed: `pandas numpy matplotlib seaborn`

### Running Complete Validation
```bash
# Navigate to validation directory
cd /mnt/mypassport/cyberrange_data/runs/evaluation/suricata_validation

# Run complete validation (experiments + analysis)
./run_suricata_validation.sh

# Or run with custom parameters
./run_suricata_validation.sh --runs 5
```

### Analysis Only (if experiments already completed)
```bash
./run_suricata_validation.sh --analysis-only
```

## 📊 What Gets Validated

### 1. Reproducibility Assessment
- **Group A (No Suricata)**: ✅ Already completed - excellent reproducibility
- **Group B (With Suricata)**: Tests if Suricata maintains reproducibility

### 2. Cross-Configuration Consistency  
- Compares event counts between Group A and Group B
- Validates that Suricata doesn't alter malicious behavior
- Ensures similar attack success rates

### 3. Suricata Monitoring Effectiveness
- Verifies alert generation for attack activities
- Checks alert consistency across runs
- Validates monitoring without interference

## 🏆 Success Criteria

| Criterion | Threshold | Description |
|-----------|-----------|-------------|
| **Reproducibility** | CV < 10% | Event counts consistent within group |
| **Cross-Group Consistency** | Variance < 10% | Similar counts between A/B groups |
| **Attack Stage Conformity** | Qualitative | Same attack progression patterns |
| **Alert Generation** | Quantitative | Appropriate Suricata alerts |

## 📁 Output Structure

```
suricata_validation/
├── comparison_results/          # JSON analysis results
│   ├── suricata_validation_report.json
│   ├── group_a_analysis.json
│   ├── group_b_analysis.json
│   └── group_comparison.json
├── validation_outputs/          # Visualizations
│   ├── reproducibility_comparison.png
│   ├── consistency_analysis.png
│   └── suricata_impact.png
└── with_suri/                   # Group B experiment data
    ├── run_01/
    ├── run_02/
    └── run_03/
```

## 🔍 Interpreting Results

### PASS Conditions
- All reproducibility metrics show CV < 10%
- Cross-group variance < 10% for key metrics
- Suricata generates appropriate alerts
- No significant performance degradation

### FAIL Conditions  
- High variance within Group B (CV > 10%)
- Significant differences between groups (>10%)
- Missing or inconsistent Suricata alerts
- Evidence of traffic blocking or interference

## 🛠 Troubleshooting

### Common Issues
1. **Missing Group A Data**: Ensure baseline experiments completed
2. **Python Dependencies**: Install required packages
3. **Suricata Configuration**: Check scenario YAML file
4. **Permissions**: Ensure write access to SSD directories

### Manual Analysis
```bash
# Run validation script directly
python3 analysis/validate_suricata_impact.py --verbose

# Check specific experiment data
ls -la with_suri/run_*/output/
```

## 📈 Expected Timeline
- **Group B Experiments**: ~3 hours (3 runs × 1 hour each)
- **Analysis**: ~10 minutes
- **Report Generation**: ~5 minutes
- **Total**: ~3.5 hours

## 🎓 Academic Context

This validation implements the assessment framework suggested by the supervisor:

> "If you run the same scenario 3 times, your reproducibility success criteria should be they all have the similar (if not exactly the same) number of malicious/benign events. You could take this even further and rerun the scenario without/with suricata, producing additional logs that offer a different perspective and does not change the malicious behaviour resulting in similar counts as before."

The framework validates:
- ✅ **Reproducibility**: Group B consistency
- ✅ **Cross-Configuration**: A vs B comparison  
- ✅ **Behavior Preservation**: Unchanged malicious patterns
- ✅ **Monitoring Value**: Additional Suricata perspective
