#!/usr/bin/env python3
"""
Suricata Impact Validation Script

This script implements the validation framework proposed by the supervisor to assess
the impact of Suricata on CyberRange reproducibility and behavior consistency.

Key Assessment Criteria:
1. Reproducibility: Similar event counts across runs with Suricata
2. Cross-configuration consistency: Compare with/without Suricata results
3. Attack stage conformity: Ensure consistent attack progression
4. Monitoring effectiveness: Validate Suricata alert generation

Author: CyberRange Validation Framework
Date: 2025-09-04
"""

import json
import pandas as pd
import numpy as np
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Tuple, Optional
import logging
from datetime import datetime
import argparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SuricataValidationFramework:
    """
    Framework for validating Suricata impact on CyberRange experiments
    """
    
    def __init__(self, base_path: str = "/mnt/mypassport/cyberrange_data/runs"):
        self.base_path = Path(base_path)
        self.group_a_path = self.base_path / "A_no_suri"
        self.group_b_path = self.base_path / "suricata_validation" / "with_suri"
        self.results_path = self.base_path / "evaluation" / "suricata_validation" / "comparison_results"
        self.output_path = self.base_path / "evaluation" / "suricata_validation" / "validation_outputs"
        
        # Create output directories
        self.results_path.mkdir(parents=True, exist_ok=True)
        self.output_path.mkdir(parents=True, exist_ok=True)
        
        # Validation thresholds
        self.reproducibility_threshold = 0.10  # 10% CV threshold
        self.consistency_threshold = 0.10      # 10% variance between groups
        
    def load_experiment_data(self, experiment_path: Path) -> Dict:
        """Load data from a single experiment run"""
        try:
            data = {}
            
            # Load network traffic data
            network_csv = experiment_path / "output" / "network_traffic.csv"
            if network_csv.exists():
                data['network_traffic'] = pd.read_csv(network_csv)
            
            # Load attack data
            attack_csv = experiment_path / "output" / "attacker_attacks.csv"
            if attack_csv.exists():
                data['attacks'] = pd.read_csv(attack_csv)
            
            # Load metadata
            metadata_json = experiment_path / "output" / "experiment_metadata.json"
            if metadata_json.exists():
                with open(metadata_json, 'r') as f:
                    data['metadata'] = json.load(f)
            
            # Load Suricata logs if available
            suricata_log = experiment_path / "suricata.log"
            if suricata_log.exists():
                data['suricata_alerts'] = self._parse_suricata_log(suricata_log)
            
            return data
            
        except Exception as e:
            logger.error(f"Error loading experiment data from {experiment_path}: {e}")
            return {}
    
    def _parse_suricata_log(self, log_path: Path) -> List[Dict]:
        """Parse Suricata log file for alerts"""
        alerts = []
        try:
            with open(log_path, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            alert = json.loads(line)
                            alerts.append(alert)
                        except json.JSONDecodeError:
                            continue
            return alerts
        except Exception as e:
            logger.error(f"Error parsing Suricata log {log_path}: {e}")
            return []
    
    def analyze_group_reproducibility(self, group_path: Path, group_name: str) -> Dict:
        """Analyze reproducibility within a group (multiple runs)"""
        logger.info(f"Analyzing reproducibility for {group_name}")
        
        runs = []
        run_dirs = [d for d in group_path.iterdir() if d.is_dir() and d.name.startswith('run_')]
        
        for run_dir in sorted(run_dirs):
            logger.info(f"Processing {run_dir.name}")
            data = self.load_experiment_data(run_dir)
            if data:
                runs.append({
                    'run_id': run_dir.name,
                    'data': data
                })
        
        if len(runs) < 2:
            logger.warning(f"Insufficient runs for reproducibility analysis in {group_name}")
            return {}
        
        # Calculate metrics for each run
        metrics = []
        for run in runs:
            run_metrics = self._calculate_run_metrics(run['data'])
            run_metrics['run_id'] = run['run_id']
            metrics.append(run_metrics)
        
        # Analyze reproducibility
        reproducibility = self._analyze_reproducibility_metrics(metrics)
        reproducibility['group_name'] = group_name
        reproducibility['total_runs'] = len(runs)
        
        return reproducibility
    
    def _calculate_run_metrics(self, data: Dict) -> Dict:
        """Calculate key metrics for a single run"""
        metrics = {}
        
        # Network traffic metrics
        if 'network_traffic' in data:
            df = data['network_traffic']
            metrics['total_flows'] = len(df)
            metrics['malicious_flows'] = len(df[df.get('label', '') == 'malicious'])
            metrics['benign_flows'] = len(df[df.get('label', '') == 'benign'])
        
        # Attack metrics
        if 'attacks' in data:
            attacks_df = data['attacks']
            metrics['total_attacks'] = len(attacks_df)
            
            # Attack type distribution
            if 'attack_type' in attacks_df.columns:
                attack_types = attacks_df['attack_type'].value_counts().to_dict()
                for attack_type, count in attack_types.items():
                    metrics[f'attack_{attack_type.lower().replace(" ", "_")}'] = count
        
        # Suricata metrics
        if 'suricata_alerts' in data:
            alerts = data['suricata_alerts']
            metrics['suricata_alerts_total'] = len(alerts)
            
            # Alert severity distribution
            severity_counts = {}
            for alert in alerts:
                severity = alert.get('alert', {}).get('severity', 'unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            for severity, count in severity_counts.items():
                metrics[f'suricata_severity_{severity}'] = count
        
        return metrics
    
    def _analyze_reproducibility_metrics(self, metrics_list: List[Dict]) -> Dict:
        """Analyze reproducibility across multiple runs"""
        if len(metrics_list) < 2:
            return {}
        
        # Convert to DataFrame for easier analysis
        df = pd.DataFrame(metrics_list)
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        reproducibility = {
            'metrics_analysis': {},
            'overall_assessment': {},
            'detailed_stats': {}
        }
        
        for col in numeric_cols:
            if col == 'run_id':
                continue
                
            values = df[col].dropna()
            if len(values) < 2:
                continue
            
            mean_val = values.mean()
            std_val = values.std()
            cv = (std_val / mean_val) if mean_val != 0 else 0
            
            reproducibility['metrics_analysis'][col] = {
                'mean': float(mean_val),
                'std': float(std_val),
                'cv': float(cv),
                'min': float(values.min()),
                'max': float(values.max()),
                'reproducible': cv < self.reproducibility_threshold
            }
        
        # Overall assessment
        reproducible_metrics = sum(1 for m in reproducibility['metrics_analysis'].values() 
                                 if m['reproducible'])
        total_metrics = len(reproducibility['metrics_analysis'])
        
        reproducibility['overall_assessment'] = {
            'reproducible_metrics_count': reproducible_metrics,
            'total_metrics_count': total_metrics,
            'reproducibility_rate': reproducible_metrics / total_metrics if total_metrics > 0 else 0,
            'passes_threshold': reproducible_metrics / total_metrics >= 0.8 if total_metrics > 0 else False
        }
        
        return reproducibility
    
    def compare_groups(self, group_a_results: Dict, group_b_results: Dict) -> Dict:
        """Compare results between Group A (no Suricata) and Group B (with Suricata)"""
        logger.info("Comparing Group A vs Group B")
        
        comparison = {
            'cross_group_analysis': {},
            'consistency_assessment': {},
            'suricata_impact': {}
        }
        
        # Compare mean values of key metrics
        group_a_metrics = group_a_results.get('metrics_analysis', {})
        group_b_metrics = group_b_results.get('metrics_analysis', {})
        
        common_metrics = set(group_a_metrics.keys()) & set(group_b_metrics.keys())
        
        for metric in common_metrics:
            a_mean = group_a_metrics[metric]['mean']
            b_mean = group_b_metrics[metric]['mean']
            
            if a_mean != 0:
                relative_diff = abs(b_mean - a_mean) / a_mean
                consistent = relative_diff < self.consistency_threshold
            else:
                relative_diff = 0
                consistent = b_mean == 0
            
            comparison['cross_group_analysis'][metric] = {
                'group_a_mean': a_mean,
                'group_b_mean': b_mean,
                'absolute_diff': b_mean - a_mean,
                'relative_diff': relative_diff,
                'consistent': consistent
            }
        
        # Overall consistency assessment
        consistent_metrics = sum(1 for m in comparison['cross_group_analysis'].values() 
                               if m['consistent'])
        total_compared = len(comparison['cross_group_analysis'])
        
        comparison['consistency_assessment'] = {
            'consistent_metrics_count': consistent_metrics,
            'total_compared_metrics': total_compared,
            'consistency_rate': consistent_metrics / total_compared if total_compared > 0 else 0,
            'passes_consistency_check': consistent_metrics / total_compared >= 0.8 if total_compared > 0 else False
        }
        
        # Suricata-specific impact analysis
        if 'suricata_alerts_total' in group_b_metrics:
            comparison['suricata_impact'] = {
                'alerts_generated': True,
                'average_alerts_per_run': group_b_metrics['suricata_alerts_total']['mean'],
                'alert_consistency': group_b_metrics['suricata_alerts_total']['reproducible']
            }
        
        return comparison
    
    def generate_validation_report(self, group_a_results: Dict, group_b_results: Dict, 
                                 comparison_results: Dict) -> Dict:
        """Generate comprehensive validation report"""
        logger.info("Generating validation report")
        
        report = {
            'validation_summary': {},
            'detailed_results': {
                'group_a': group_a_results,
                'group_b': group_b_results,
                'comparison': comparison_results
            },
            'recommendations': [],
            'timestamp': datetime.now().isoformat()
        }
        
        # Validation summary
        group_a_passes = group_a_results.get('overall_assessment', {}).get('passes_threshold', False)
        group_b_passes = group_b_results.get('overall_assessment', {}).get('passes_threshold', False)
        consistency_passes = comparison_results.get('consistency_assessment', {}).get('passes_consistency_check', False)
        
        report['validation_summary'] = {
            'group_a_reproducibility': 'PASS' if group_a_passes else 'FAIL',
            'group_b_reproducibility': 'PASS' if group_b_passes else 'FAIL',
            'cross_group_consistency': 'PASS' if consistency_passes else 'FAIL',
            'overall_validation': 'PASS' if all([group_a_passes, group_b_passes, consistency_passes]) else 'FAIL'
        }
        
        # Generate recommendations
        if not group_b_passes:
            report['recommendations'].append(
                "Group B reproducibility is below threshold. Consider investigating Suricata configuration or system performance."
            )
        
        if not consistency_passes:
            report['recommendations'].append(
                "Cross-group consistency is below threshold. Suricata may be impacting experiment behavior."
            )
        
        if group_a_passes and group_b_passes and consistency_passes:
            report['recommendations'].append(
                "All validation criteria passed. Suricata integration is successful with minimal impact on reproducibility."
            )
        
        return report
    
    def create_visualizations(self, group_a_results: Dict, group_b_results: Dict, 
                            comparison_results: Dict):
        """Create visualization charts for validation results"""
        logger.info("Creating validation visualizations")
        
        # Set up the plotting style
        plt.style.use('default')
        sns.set_palette("husl")
        
        # 1. Reproducibility comparison chart
        self._plot_reproducibility_comparison(group_a_results, group_b_results)
        
        # 2. Cross-group consistency chart
        self._plot_consistency_analysis(comparison_results)
        
        # 3. Suricata impact visualization
        if 'suricata_impact' in comparison_results:
            self._plot_suricata_impact(comparison_results['suricata_impact'])
    
    def _plot_reproducibility_comparison(self, group_a_results: Dict, group_b_results: Dict):
        """Plot reproducibility comparison between groups"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Extract CV values for key metrics
        def extract_cv_values(results, metric_filter=None):
            metrics = results.get('metrics_analysis', {})
            if metric_filter:
                metrics = {k: v for k, v in metrics.items() if any(f in k for f in metric_filter)}
            return {k: v['cv'] for k, v in metrics.items()}
        
        key_metrics = ['total_flows', 'malicious_flows', 'benign_flows', 'total_attacks']
        group_a_cvs = extract_cv_values(group_a_results, key_metrics)
        group_b_cvs = extract_cv_values(group_b_results, key_metrics)
        
        # Plot Group A
        if group_a_cvs:
            ax1.bar(range(len(group_a_cvs)), list(group_a_cvs.values()))
            ax1.axhline(y=self.reproducibility_threshold, color='r', linestyle='--', 
                       label=f'Threshold ({self.reproducibility_threshold:.1%})')
            ax1.set_title('Group A (No Suricata) - Reproducibility')
            ax1.set_ylabel('Coefficient of Variation')
            ax1.set_xticks(range(len(group_a_cvs)))
            ax1.set_xticklabels(list(group_a_cvs.keys()), rotation=45)
            ax1.legend()
        
        # Plot Group B
        if group_b_cvs:
            ax2.bar(range(len(group_b_cvs)), list(group_b_cvs.values()))
            ax2.axhline(y=self.reproducibility_threshold, color='r', linestyle='--', 
                       label=f'Threshold ({self.reproducibility_threshold:.1%})')
            ax2.set_title('Group B (With Suricata) - Reproducibility')
            ax2.set_ylabel('Coefficient of Variation')
            ax2.set_xticks(range(len(group_b_cvs)))
            ax2.set_xticklabels(list(group_b_cvs.keys()), rotation=45)
            ax2.legend()
        
        plt.tight_layout()
        plt.savefig(self.output_path / 'reproducibility_comparison.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _plot_consistency_analysis(self, comparison_results: Dict):
        """Plot cross-group consistency analysis"""
        cross_analysis = comparison_results.get('cross_group_analysis', {})
        if not cross_analysis:
            return
        
        fig, ax = plt.subplots(figsize=(12, 8))
        
        metrics = list(cross_analysis.keys())
        relative_diffs = [cross_analysis[m]['relative_diff'] for m in metrics]
        colors = ['green' if cross_analysis[m]['consistent'] else 'red' for m in metrics]
        
        bars = ax.bar(range(len(metrics)), relative_diffs, color=colors, alpha=0.7)
        ax.axhline(y=self.consistency_threshold, color='red', linestyle='--', 
                  label=f'Consistency Threshold ({self.consistency_threshold:.1%})')
        ax.axhline(y=-self.consistency_threshold, color='red', linestyle='--')
        
        ax.set_title('Cross-Group Consistency Analysis\n(Group A vs Group B)')
        ax.set_ylabel('Relative Difference')
        ax.set_xlabel('Metrics')
        ax.set_xticks(range(len(metrics)))
        ax.set_xticklabels(metrics, rotation=45, ha='right')
        ax.legend()
        
        # Add value labels on bars
        for bar, diff in zip(bars, relative_diffs):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.001,
                   f'{diff:.2%}', ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig(self.output_path / 'consistency_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _plot_suricata_impact(self, suricata_impact: Dict):
        """Plot Suricata-specific impact metrics"""
        if not suricata_impact.get('alerts_generated', False):
            return
        
        fig, ax = plt.subplots(figsize=(8, 6))
        
        # Simple bar chart showing alert generation
        categories = ['Average Alerts\nper Run']
        values = [suricata_impact.get('average_alerts_per_run', 0)]
        
        bars = ax.bar(categories, values, color='blue', alpha=0.7)
        ax.set_title('Suricata Alert Generation')
        ax.set_ylabel('Number of Alerts')
        
        # Add value labels
        for bar, value in zip(bars, values):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                   f'{value:.1f}', ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig(self.output_path / 'suricata_impact.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def run_validation(self) -> Dict:
        """Run complete validation analysis"""
        logger.info("Starting Suricata validation analysis")
        
        # Analyze Group A (baseline)
        group_a_results = self.analyze_group_reproducibility(self.group_a_path, "Group A (No Suricata)")
        
        # Analyze Group B (with Suricata)
        group_b_results = self.analyze_group_reproducibility(self.group_b_path, "Group B (With Suricata)")
        
        # Compare groups
        comparison_results = self.compare_groups(group_a_results, group_b_results)
        
        # Generate comprehensive report
        validation_report = self.generate_validation_report(group_a_results, group_b_results, comparison_results)
        
        # Create visualizations
        self.create_visualizations(group_a_results, group_b_results, comparison_results)
        
        # Save results
        self._save_results(validation_report)
        
        logger.info("Validation analysis completed")
        return validation_report
    
    def _save_results(self, validation_report: Dict):
        """Save validation results to files"""
        # Save main validation report
        with open(self.results_path / 'suricata_validation_report.json', 'w') as f:
            json.dump(validation_report, f, indent=2)
        
        # Save individual components
        if 'detailed_results' in validation_report:
            detailed = validation_report['detailed_results']
            
            if 'group_a' in detailed:
                with open(self.results_path / 'group_a_analysis.json', 'w') as f:
                    json.dump(detailed['group_a'], f, indent=2)
            
            if 'group_b' in detailed:
                with open(self.results_path / 'group_b_analysis.json', 'w') as f:
                    json.dump(detailed['group_b'], f, indent=2)
            
            if 'comparison' in detailed:
                with open(self.results_path / 'group_comparison.json', 'w') as f:
                    json.dump(detailed['comparison'], f, indent=2)
        
        logger.info(f"Results saved to {self.results_path}")

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Suricata Impact Validation Framework')
    parser.add_argument('--base-path', default='/mnt/mypassport/cyberrange_data/runs',
                       help='Base path for experiment data')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize validation framework
    validator = SuricataValidationFramework(args.base_path)
    
    # Run validation
    try:
        results = validator.run_validation()
        
        # Print summary
        summary = results.get('validation_summary', {})
        print("\n" + "="*50)
        print("SURICATA VALIDATION RESULTS")
        print("="*50)
        print(f"Group A Reproducibility: {summary.get('group_a_reproducibility', 'UNKNOWN')}")
        print(f"Group B Reproducibility: {summary.get('group_b_reproducibility', 'UNKNOWN')}")
        print(f"Cross-Group Consistency: {summary.get('cross_group_consistency', 'UNKNOWN')}")
        print(f"Overall Validation: {summary.get('overall_validation', 'UNKNOWN')}")
        print("="*50)
        
        if results.get('recommendations'):
            print("\nRecommendations:")
            for i, rec in enumerate(results['recommendations'], 1):
                print(f"{i}. {rec}")
        
        return 0 if summary.get('overall_validation') == 'PASS' else 1
        
    except Exception as e:
        logger.error(f"Validation failed: {e}")
        return 1

if __name__ == "__main__":
    exit(main())
