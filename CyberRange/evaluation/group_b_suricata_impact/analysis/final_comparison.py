#!/usr/bin/env python3
"""
Final Suricata Validation Comparison

Complete analysis of Group A vs Group B data for Suricata validation.
"""

import json
import pandas as pd
import numpy as np
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_attack_data(run_path):
    """Load attack data from a run directory"""
    attack_files = list(run_path.glob("**/attacker_attacks.csv"))
    if not attack_files:
        return None
    
    # Use the most recent or main attack file
    attack_file = attack_files[0]
    try:
        df = pd.read_csv(attack_file)
        return df
    except Exception as e:
        logger.error(f"Error loading {attack_file}: {e}")
        return None

def analyze_group_data(group_path, group_name):
    """Analyze data for a group (A or B)"""
    logger.info(f"Analyzing {group_name}...")
    
    runs_data = []
    for run_dir in sorted(group_path.glob("run_*")):
        if not run_dir.is_dir():
            continue
            
        logger.info(f"  Processing {run_dir.name}")
        
        # Load attack data
        attack_df = load_attack_data(run_dir)
        if attack_df is not None:
            attack_count = len(attack_df)
            
            # Analyze attack types
            attack_types = {}
            if 'attack_type' in attack_df.columns:
                attack_types = attack_df['attack_type'].value_counts().to_dict()
            
            runs_data.append({
                'run': run_dir.name,
                'total_attacks': attack_count,
                'attack_types': attack_types,
                'has_data': True
            })
            logger.info(f"    Attacks: {attack_count}")
        else:
            runs_data.append({
                'run': run_dir.name,
                'total_attacks': 0,
                'attack_types': {},
                'has_data': False
            })
            logger.info(f"    No attack data found")
    
    return runs_data

def calculate_reproducibility_metrics(runs_data):
    """Calculate reproducibility metrics for a group"""
    valid_runs = [run for run in runs_data if run['has_data']]
    if len(valid_runs) < 2:
        return None
    
    attack_counts = [run['total_attacks'] for run in valid_runs]
    
    mean_attacks = np.mean(attack_counts)
    std_attacks = np.std(attack_counts)
    cv = std_attacks / mean_attacks if mean_attacks > 0 else 0
    
    return {
        'runs_count': len(valid_runs),
        'attack_counts': attack_counts,
        'mean': mean_attacks,
        'std': std_attacks,
        'cv': cv,
        'min': np.min(attack_counts),
        'max': np.max(attack_counts),
        'reproducible': cv < 0.10  # 10% threshold
    }

def compare_groups(group_a_data, group_b_data):
    """Compare Group A and Group B"""
    logger.info("Comparing groups...")
    
    # Get valid runs from each group
    group_a_valid = [run for run in group_a_data if run['has_data']]
    group_b_valid = [run for run in group_b_data if run['has_data']]
    
    if not group_a_valid or not group_b_valid:
        logger.warning("Insufficient data for comparison")
        return None
    
    # Calculate means
    a_mean = np.mean([run['total_attacks'] for run in group_a_valid])
    b_mean = np.mean([run['total_attacks'] for run in group_b_valid])
    
    # Calculate relative difference
    if a_mean > 0:
        relative_diff = abs(b_mean - a_mean) / a_mean
        consistent = relative_diff < 0.10  # 10% threshold
    else:
        relative_diff = 0
        consistent = b_mean == 0
    
    return {
        'group_a_mean': a_mean,
        'group_b_mean': b_mean,
        'absolute_diff': b_mean - a_mean,
        'relative_diff': relative_diff,
        'consistent': consistent,
        'group_a_runs': len(group_a_valid),
        'group_b_runs': len(group_b_valid)
    }

def create_comparison_chart(group_a_metrics, group_b_metrics, output_path):
    """Create comparison visualization"""
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
    
    # 1. Attack counts comparison
    if group_a_metrics and group_b_metrics:
        ax1.bar(['Group A\n(No Suricata)', 'Group B\n(With Suricata)'], 
                [group_a_metrics['mean'], group_b_metrics['mean']], 
                color=['blue', 'orange'], alpha=0.7)
        ax1.set_title('Average Attack Counts')
        ax1.set_ylabel('Number of Attacks')
        
        # Add error bars
        ax1.errorbar(['Group A\n(No Suricata)', 'Group B\n(With Suricata)'], 
                    [group_a_metrics['mean'], group_b_metrics['mean']],
                    yerr=[group_a_metrics['std'], group_b_metrics['std']],
                    fmt='none', color='black', capsize=5)
    
    # 2. Coefficient of Variation comparison
    if group_a_metrics and group_b_metrics:
        ax2.bar(['Group A', 'Group B'], 
                [group_a_metrics['cv'], group_b_metrics['cv']], 
                color=['blue', 'orange'], alpha=0.7)
        ax2.axhline(y=0.10, color='red', linestyle='--', label='Threshold (10%)')
        ax2.set_title('Reproducibility (Coefficient of Variation)')
        ax2.set_ylabel('CV')
        ax2.legend()
    
    # 3. Individual run data
    if group_a_metrics:
        ax3.plot(range(1, len(group_a_metrics['attack_counts'])+1), 
                group_a_metrics['attack_counts'], 'bo-', label='Group A', markersize=8)
    if group_b_metrics:
        ax3.plot(range(1, len(group_b_metrics['attack_counts'])+1), 
                group_b_metrics['attack_counts'], 'ro-', label='Group B', markersize=8)
    ax3.set_title('Attack Counts by Run')
    ax3.set_xlabel('Run Number')
    ax3.set_ylabel('Attack Count')
    ax3.legend()
    ax3.grid(True, alpha=0.3)
    
    # 4. Summary statistics
    ax4.axis('off')
    summary_text = "Validation Summary\n\n"
    
    if group_a_metrics:
        summary_text += f"Group A (No Suricata):\n"
        summary_text += f"  Runs: {group_a_metrics['runs_count']}\n"
        summary_text += f"  Mean: {group_a_metrics['mean']:.1f}\n"
        summary_text += f"  CV: {group_a_metrics['cv']:.3f} ({group_a_metrics['cv']*100:.1f}%)\n"
        summary_text += f"  Reproducible: {'✅' if group_a_metrics['reproducible'] else '❌'}\n\n"
    
    if group_b_metrics:
        summary_text += f"Group B (With Suricata):\n"
        summary_text += f"  Runs: {group_b_metrics['runs_count']}\n"
        summary_text += f"  Mean: {group_b_metrics['mean']:.1f}\n"
        summary_text += f"  CV: {group_b_metrics['cv']:.3f} ({group_b_metrics['cv']*100:.1f}%)\n"
        summary_text += f"  Reproducible: {'✅' if group_b_metrics['reproducible'] else '❌'}\n"
    
    ax4.text(0.1, 0.9, summary_text, transform=ax4.transAxes, 
            fontsize=12, verticalalignment='top', fontfamily='monospace')
    
    plt.tight_layout()
    plt.savefig(output_path / 'suricata_validation_comparison.png', dpi=300, bbox_inches='tight')
    plt.close()
    
    logger.info(f"Comparison chart saved to: {output_path / 'suricata_validation_comparison.png'}")

def generate_final_report(group_a_data, group_b_data, group_a_metrics, group_b_metrics, comparison):
    """Generate final validation report"""
    
    # Determine validation results
    group_a_pass = group_a_metrics['reproducible'] if group_a_metrics else False
    group_b_pass = group_b_metrics['reproducible'] if group_b_metrics else False
    consistency_pass = comparison['consistent'] if comparison else False
    
    overall_pass = group_a_pass and group_b_pass and consistency_pass
    
    report = {
        'validation_summary': {
            'group_a_reproducibility': 'PASS' if group_a_pass else 'FAIL',
            'group_b_reproducibility': 'PASS' if group_b_pass else 'FAIL', 
            'cross_group_consistency': 'PASS' if consistency_pass else 'FAIL',
            'overall_validation': 'PASS' if overall_pass else 'FAIL'
        },
        'detailed_analysis': {
            'group_a': {
                'data': group_a_data,
                'metrics': group_a_metrics
            },
            'group_b': {
                'data': group_b_data,
                'metrics': group_b_metrics
            },
            'comparison': comparison
        },
        'recommendations': [],
        'timestamp': datetime.now().isoformat()
    }
    
    # Generate recommendations
    if not group_a_pass:
        report['recommendations'].append("Group A shows poor reproducibility. Check experimental setup.")
    
    if not group_b_pass:
        report['recommendations'].append("Group B shows poor reproducibility. Suricata may be affecting consistency.")
    
    if not consistency_pass:
        report['recommendations'].append("Groups show significant differences. Suricata may be impacting attack behavior.")
    
    if overall_pass:
        report['recommendations'].append("✅ All validation criteria passed! Suricata integration is successful.")
    
    return report

def main():
    """Main analysis function"""
    logger.info("=== Final Suricata Validation Analysis ===")
    
    # Paths
    base_path = Path("/mnt/mypassport/cyberrange_data/runs")
    group_a_path = base_path / "A_no_suri"
    group_b_path = base_path / "suricata_validation" / "with_suri"
    output_path = base_path / "evaluation" / "suricata_validation" / "validation_outputs"
    results_path = base_path / "evaluation" / "suricata_validation" / "comparison_results"
    
    # Create output directories
    output_path.mkdir(parents=True, exist_ok=True)
    results_path.mkdir(parents=True, exist_ok=True)
    
    # Analyze both groups
    group_a_data = analyze_group_data(group_a_path, "Group A (No Suricata)")
    group_b_data = analyze_group_data(group_b_path, "Group B (With Suricata)")
    
    # Calculate metrics
    group_a_metrics = calculate_reproducibility_metrics(group_a_data)
    group_b_metrics = calculate_reproducibility_metrics(group_b_data)
    
    # Compare groups
    comparison = compare_groups(group_a_data, group_b_data)
    
    # Create visualization
    if group_a_metrics or group_b_metrics:
        create_comparison_chart(group_a_metrics, group_b_metrics, output_path)
    
    # Generate final report
    final_report = generate_final_report(group_a_data, group_b_data, group_a_metrics, group_b_metrics, comparison)
    
    # Save results
    with open(results_path / 'final_validation_report.json', 'w') as f:
        json.dump(final_report, f, indent=2)
    
    # Print summary
    logger.info("\n" + "="*60)
    logger.info("FINAL VALIDATION RESULTS")
    logger.info("="*60)
    
    summary = final_report['validation_summary']
    logger.info(f"Group A Reproducibility: {summary['group_a_reproducibility']}")
    logger.info(f"Group B Reproducibility: {summary['group_b_reproducibility']}")
    logger.info(f"Cross-Group Consistency: {summary['cross_group_consistency']}")
    logger.info(f"Overall Validation: {summary['overall_validation']}")
    
    if final_report['recommendations']:
        logger.info("\nRecommendations:")
        for i, rec in enumerate(final_report['recommendations'], 1):
            logger.info(f"{i}. {rec}")
    
    logger.info(f"\nDetailed results: {results_path / 'final_validation_report.json'}")
    logger.info(f"Visualization: {output_path / 'suricata_validation_comparison.png'}")
    
    return 0 if summary['overall_validation'] == 'PASS' else 1

if __name__ == "__main__":
    exit(main())
