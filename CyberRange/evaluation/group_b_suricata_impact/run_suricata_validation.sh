#!/bin/bash
#
# Suricata Validation Execution Script
#
# This script executes the complete Suricata validation framework:
# 1. Runs Group B experiments (with Suricata enabled)
# 2. Executes cross-group analysis
# 3. Generates validation reports and visualizations
#
# Usage: ./run_suricata_validation.sh [options]
#

set -e  # Exit on any error

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="/home/jiayi/SecurityLogs/CyberRange"
VALIDATION_DIR="/mnt/mypassport/cyberrange_data/runs/evaluation/suricata_validation"
SCENARIO_CONFIG="scenarios/test_all_features_with_suricata.yaml"
GROUP_B_RUNS=3

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if we're in the right directory
    if [[ ! -f "$PROJECT_ROOT/run_scenario.py" ]]; then
        error "Project root not found. Please run from CyberRange directory."
        exit 1
    fi
    
    # Check if Suricata scenario exists
    if [[ ! -f "$PROJECT_ROOT/$SCENARIO_CONFIG" ]]; then
        error "Suricata scenario config not found: $SCENARIO_CONFIG"
        exit 1
    fi
    
    # Check if Group A results exist (baseline)
    if [[ ! -d "/mnt/mypassport/cyberrange_data/runs/A_no_suri" ]]; then
        error "Group A baseline results not found. Please run Group A experiments first."
        exit 1
    fi
    
    # Check Python dependencies
    python3 -c "import pandas, numpy, matplotlib, seaborn" 2>/dev/null || {
        error "Required Python packages not found. Please install: pandas numpy matplotlib seaborn"
        exit 1
    }
    
    success "Prerequisites check passed"
}

# Create Group B directory structure
setup_group_b() {
    log "Setting up Group B directory structure..."
    
    local group_b_dir="/mnt/mypassport/cyberrange_data/runs/suricata_validation/with_suri"
    mkdir -p "$group_b_dir"
    
    success "Group B directory created: $group_b_dir"
}

# Run a single Group B experiment
run_group_b_experiment() {
    local run_number=$1
    local run_id="run_$(printf "%02d" $run_number)"
    
    log "Starting Group B experiment: $run_id"
    
    cd "$PROJECT_ROOT"
    
    # Set environment variables for this run
    export EXPERIMENT_GROUP="B_with_suri"
    export RUN_ID="$run_id"
    export SURICATA_ENABLED="true"
    
    # Run the experiment
    if python3 run_scenario.py --config "$SCENARIO_CONFIG"; then
        success "Group B experiment $run_id completed successfully"
        
        # Move results to Group B directory
        # Check multiple possible source locations
        local possible_sources=(
            "logs/test-all-features-with-suricata_*"
            "/mnt/mypassport/cyberrange_data/runs/suricata_validation/$run_id"
            "logs/$run_id"
        )
        local target_dir="/mnt/mypassport/cyberrange_data/runs/suricata_validation/with_suri/$run_id"
        
        local source_found=false
        for source_pattern in "${possible_sources[@]}"; do
            for source_dir in $source_pattern; do
                if [[ -d "$source_dir" ]]; then
                    log "Moving results from $source_dir to $target_dir"
                    mv "$source_dir" "$target_dir"
                    source_found=true
                    break 2
                fi
            done
        done
        
        if [[ "$source_found" != "true" ]]; then
            warning "Results directory not found automatically. Checking logs directory..."
            # List what was created
            ls -la logs/ | grep "$(date +%Y%m%d)" || true
        fi
        
        return 0
    else
        error "Group B experiment $run_id failed"
        return 1
    fi
}

# Run all Group B experiments
run_group_b_experiments() {
    log "Running Group B experiments (with Suricata)..."
    
    local failed_runs=0
    
    for ((i=1; i<=GROUP_B_RUNS; i++)); do
        log "Running experiment $i of $GROUP_B_RUNS"
        
        if ! run_group_b_experiment $i; then
            ((failed_runs++))
            error "Experiment $i failed"
        fi
        
        # Wait between runs to ensure clean state
        if [[ $i -lt $GROUP_B_RUNS ]]; then
            log "Waiting 30 seconds before next run..."
            sleep 30
        fi
    done
    
    if [[ $failed_runs -eq 0 ]]; then
        success "All Group B experiments completed successfully"
        return 0
    else
        error "$failed_runs out of $GROUP_B_RUNS experiments failed"
        return 1
    fi
}

# Run validation analysis
run_validation_analysis() {
    log "Running Suricata validation analysis..."
    
    cd "$VALIDATION_DIR"
    
    if python3 analysis/validate_suricata_impact.py --verbose; then
        success "Validation analysis completed successfully"
        
        # Display results location
        log "Results saved to:"
        log "  - JSON reports: $VALIDATION_DIR/comparison_results/"
        log "  - Visualizations: $VALIDATION_DIR/validation_outputs/"
        
        return 0
    else
        error "Validation analysis failed"
        return 1
    fi
}

# Generate summary report
generate_summary() {
    log "Generating validation summary..."
    
    local report_file="$VALIDATION_DIR/comparison_results/suricata_validation_report.json"
    
    if [[ -f "$report_file" ]]; then
        # Extract key results using Python
        python3 -c "
import json
import sys

try:
    with open('$report_file', 'r') as f:
        report = json.load(f)
    
    summary = report.get('validation_summary', {})
    
    print('\\n' + '='*60)
    print('SURICATA VALIDATION SUMMARY')
    print('='*60)
    print(f'Group A Reproducibility: {summary.get(\"group_a_reproducibility\", \"UNKNOWN\")}')
    print(f'Group B Reproducibility: {summary.get(\"group_b_reproducibility\", \"UNKNOWN\")}')
    print(f'Cross-Group Consistency: {summary.get(\"cross_group_consistency\", \"UNKNOWN\")}')
    print(f'Overall Validation: {summary.get(\"overall_validation\", \"UNKNOWN\")}')
    print('='*60)
    
    recommendations = report.get('recommendations', [])
    if recommendations:
        print('\\nRecommendations:')
        for i, rec in enumerate(recommendations, 1):
            print(f'{i}. {rec}')
    
    print('\\nDetailed results available in:')
    print(f'  {report_file}')
    print('\\n')
    
except Exception as e:
    print(f'Error reading report: {e}', file=sys.stderr)
    sys.exit(1)
"
        success "Summary generated successfully"
    else
        warning "Validation report not found: $report_file"
    fi
}

# Cleanup function
cleanup() {
    log "Cleaning up temporary files..."
    
    # Stop any running containers
    if command -v docker &> /dev/null; then
        docker stop $(docker ps -q) 2>/dev/null || true
    fi
    
    # Reset environment variables
    unset EXPERIMENT_GROUP RUN_ID SURICATA_ENABLED
    
    log "Cleanup completed"
}

# Main execution function
main() {
    log "Starting Suricata Validation Framework"
    log "======================================"
    
    # Set up cleanup trap
    trap cleanup EXIT
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --runs)
                GROUP_B_RUNS="$2"
                shift 2
                ;;
            --skip-experiments)
                SKIP_EXPERIMENTS=true
                shift
                ;;
            --analysis-only)
                ANALYSIS_ONLY=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [options]"
                echo "Options:"
                echo "  --runs N              Number of Group B runs (default: 3)"
                echo "  --skip-experiments    Skip running experiments, analyze existing data"
                echo "  --analysis-only       Only run analysis, skip experiments"
                echo "  --help, -h           Show this help message"
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Execute validation steps
    check_prerequisites
    
    if [[ "${ANALYSIS_ONLY:-false}" != "true" ]]; then
        setup_group_b
        
        if [[ "${SKIP_EXPERIMENTS:-false}" != "true" ]]; then
            run_group_b_experiments || {
                error "Group B experiments failed"
                exit 1
            }
        fi
    fi
    
    run_validation_analysis || {
        error "Validation analysis failed"
        exit 1
    }
    
    generate_summary
    
    success "Suricata validation framework completed successfully!"
    log "Check the validation outputs for detailed results and recommendations."
}

# Execute main function with all arguments
main "$@"
