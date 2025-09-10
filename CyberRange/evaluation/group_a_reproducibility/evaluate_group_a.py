#!/usr/bin/env python3
"""
A group (no Suricata) experiment evaluation code
Analyze the reproducibility and data quality of three experiments
"""

import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

class GroupAEvaluator:
    def __init__(self, base_dir="/mnt/mypassport/cyberrange_data/runs/A_no_suri"):
        self.base_dir = Path(base_dir)
        self.runs = []
        self.load_all_runs()
    
    def load_all_runs(self):
        """Load all three experiment data"""
        for run_id in range(1, 4):
            run_dir = self.base_dir / f"run_0{run_id}"
            if run_dir.exists():
                run_data = self.load_single_run(run_dir, run_id)
                if run_data:
                    self.runs.append(run_data)
                    print(f"✅ Load Run {run_id}: {run_data['total_flows']} flows")
                else:
                    print(f"❌ Run {run_id} data is incomplete")
            else:
                print(f"❌ Run {run_id} directory does not exist")
    
    def load_single_run(self, run_dir, run_id):
        """Load single experiment data"""
        try:
            # Load network traffic summary
            summary_file = run_dir / "output" / "network_traffic_summary.json"
            if not summary_file.exists():
                print(f"⚠️  Run {run_id}: missing network_traffic_summary.json")
                return None
            
            with open(summary_file, 'r') as f:
                summary = json.load(f)
            
            # Load CSV data
            csv_file = run_dir / "output" / "network_traffic.csv"
            if not csv_file.exists():
                print(f"⚠️  Run {run_id}: missing network_traffic.csv")
                return None
            
            df = pd.read_csv(csv_file)
            
            # Load attack data
            attack_file = run_dir / "output" / "attacker_attacks.csv"
            attack_df = pd.read_csv(attack_file) if attack_file.exists() else pd.DataFrame()
            
            return {
                'run_id': run_id,
                'run_dir': run_dir,
                'summary': summary,
                'network_df': df,
                'attack_df': attack_df,
                'total_flows': summary['basic_statistics']['total_flows'],
                'attack_flows': summary['basic_statistics']['attack_flows'],
                'benign_flows': summary['basic_statistics']['benign_flows'],
                'attack_percentage': summary['basic_statistics']['attack_percentage'],
                'benign_percentage': summary['basic_statistics']['benign_percentage']
            }
        except Exception as e:
            print(f"❌ Run {run_id} load failed: {e}")
            return None
    
    def calculate_reproducibility_metrics(self):
        """Calculate reproducibility metrics"""
        if len(self.runs) < 2:
            return None
        
        metrics = {}
        
        # Basic flow statistics
        total_flows = [run['total_flows'] for run in self.runs]
        attack_flows = [run['attack_flows'] for run in self.runs]
        benign_flows = [run['benign_flows'] for run in self.runs]
        
        metrics['total_flows'] = {
            'values': total_flows,
            'mean': np.mean(total_flows),
            'std': np.std(total_flows),
            'cv': np.std(total_flows) / np.mean(total_flows) * 100,
            'max_deviation': max([abs(x - np.mean(total_flows)) / np.mean(total_flows) * 100 for x in total_flows])
        }
        
        metrics['attack_flows'] = {
            'values': attack_flows,
            'mean': np.mean(attack_flows),
            'std': np.std(attack_flows),
            'cv': np.std(attack_flows) / np.mean(attack_flows) * 100,
            'max_deviation': max([abs(x - np.mean(attack_flows)) / np.mean(attack_flows) * 100 for x in attack_flows])
        }
        
        metrics['benign_flows'] = {
            'values': benign_flows,
            'mean': np.mean(benign_flows),
            'std': np.std(benign_flows),
            'cv': np.std(benign_flows) / np.mean(benign_flows) * 100,
            'max_deviation': max([abs(x - np.mean(benign_flows)) / np.mean(benign_flows) * 100 for x in benign_flows])
        }
        
        return metrics
    
    def analyze_attack_distribution(self):
        """Analyze the consistency of attack type distribution"""
        attack_distributions = []
        
        for run in self.runs:
            attack_types = run['summary']['attack_analysis']['attack_types']
            attack_distributions.append(attack_types)
        
        # Calculate the variation coefficient for each attack type
        attack_consistency = {}
        for attack_type in attack_types.keys():
            values = [dist[attack_type] for dist in attack_distributions]
            attack_consistency[attack_type] = {
                'values': values,
                'mean': np.mean(values),
                'std': np.std(values),
                'cv': np.std(values) / np.mean(values) * 100 if np.mean(values) > 0 else 0
            }
        
        return attack_consistency
    
    def generate_visualizations(self, output_dir="evaluation_outputs"):
        """Generate visualizations"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Set Chinese font
        plt.rcParams['font.sans-serif'] = ['DejaVu Sans']
        plt.rcParams['axes.unicode_minus'] = False 
        
        # 1. Flow statistics comparison chart
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle('Group A (No Suricata) - Flow Statistics Comparison', fontsize=16)
        
        # Total flows
        total_flows = [run['total_flows'] for run in self.runs]
        axes[0,0].bar([f'Run {i+1}' for i in range(len(self.runs))], total_flows, color='skyblue')
        axes[0,0].set_title('Total Flows')
        axes[0,0].set_ylabel('Count')
        
        # Attack flows
        attack_flows = [run['attack_flows'] for run in self.runs]
        axes[0,1].bar([f'Run {i+1}' for i in range(len(self.runs))], attack_flows, color='red', alpha=0.7)
        axes[0,1].set_title('Attack Flows')
        axes[0,1].set_ylabel('Count')
        
        # Benign flows
        benign_flows = [run['benign_flows'] for run in self.runs]
        axes[1,0].bar([f'Run {i+1}' for i in range(len(self.runs))], benign_flows, color='green', alpha=0.7)
        axes[1,0].set_title('Benign Flows')
        axes[1,0].set_ylabel('Count')
        
        # Attack percentage
        attack_percentages = [run['attack_percentage'] for run in self.runs]
        axes[1,1].bar([f'Run {i+1}' for i in range(len(self.runs))], attack_percentages, color='orange', alpha=0.7)
        axes[1,1].set_title('Attack Percentage')
        axes[1,1].set_ylabel('Percentage (%)')
        
        plt.tight_layout()
        plt.savefig(output_path / 'flow_statistics_comparison.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # 2. Attack type distribution comparison
        if len(self.runs) > 0:
            attack_types = list(self.runs[0]['summary']['attack_analysis']['attack_types'].keys())
            fig, ax = plt.subplots(figsize=(12, 8))
            
            x = np.arange(len(attack_types))
            width = 0.25
            
            for i, run in enumerate(self.runs):
                values = [run['summary']['attack_analysis']['attack_types'][at] for at in attack_types]
                ax.bar(x + i*width, values, width, label=f'Run {i+1}', alpha=0.8)
            
            ax.set_xlabel('Attack Types')
            ax.set_ylabel('Count')
            ax.set_title('Attack Type Distribution Comparison')
            ax.set_xticks(x + width)
            ax.set_xticklabels(attack_types, rotation=45)
            ax.legend()
            
            plt.tight_layout()
            plt.savefig(output_path / 'attack_type_distribution.png', dpi=300, bbox_inches='tight')
            plt.close()
        
        print(f"📊 Visualizations saved to: {output_path}")
    
    def generate_report(self):
        """Generate detailed evaluation report"""
        print("=" * 80)
        print("🔍 GROUP A (NO SURICATA) EVALUATION REPORT")
        print("=" * 80)
        
        # Basic statistics
        print(f"\n📊 实验概况:")
        print(f"   • Experiment次数: {len(self.runs)}")
        print(f"   • Experiment scenario: balanced-ml-dataset")
        print(f"   • Running time: 1 hour")
        print(f"   • Random seed: Fixed (20250830)")
        
        # Reproducibility analysis
        metrics = self.calculate_reproducibility_metrics()
        if metrics:
            print(f"\n🔄 Reproducibility analysis:")
            print(f"   • total flows variation coefficient: {metrics['total_flows']['cv']:.2f}%")
            print(f"   • attack flows variation coefficient: {metrics['attack_flows']['cv']:.2f}%")
            print(f"   • benign flows variation coefficient: {metrics['benign_flows']['cv']:.2f}%")
            
            print(f"\n📈 Detailed statistics:")
            for metric_name, metric_data in metrics.items():
                print(f"   {metric_name.replace('_', ' ').title()}:")
                print(f"     - Mean: {metric_data['mean']:.1f}")
                print(f"     - Standard deviation: {metric_data['std']:.1f}")
                print(f"     - Maximum deviation: {metric_data['max_deviation']:.2f}%")
                print(f"     - Reproducibility: {'✅ Excellent' if metric_data['max_deviation'] <= 5 else '✅ Good' if metric_data['max_deviation'] <= 10 else '⚠️  需改进'}")
        
        # Attack distribution analysis
        attack_consistency = self.analyze_attack_distribution()
        if attack_consistency:
            print(f"\n🎯 Attack type distribution consistency:")
            for attack_type, data in attack_consistency.items():
                print(f"   • {attack_type}: CV={data['cv']:.2f}% ({'✅ Same' if data['cv'] <= 10 else '⚠️  变化'})")
        
        # Data quality evaluation
        print(f"\n📋 Dataset quality evaluation:")
        for i, run in enumerate(self.runs, 1):
            print(f"   Run {i}:")
            print(f"     - Network traffic CSV: {'✅' if not run['network_df'].empty else '❌'}")
            print(f"     - Attack log CSV: {'✅' if not run['attack_df'].empty else '❌'}")
            print(f"     - Summary JSON: {'✅' if run['summary'] else '❌'}")
            print(f"     - Data completeness: {'✅ Complete' if not run['network_df'].empty and not run['attack_df'].empty else '⚠️  Incomplete'}")
        
        # Overall evaluation
        print(f"\n🏆 Overall evaluation:")
        if metrics:
            all_good = all(metric['max_deviation'] <= 10 for metric in metrics.values())
            print(f"   • Reproducibility: {'✅ Excellent' if all_good else '⚠️  needs improvement'}")
            print(f"   • Data quality: {'✅ Excellent' if all(not run['network_df'].empty for run in self.runs) else '⚠️  needs improvement'}")
        
        print("=" * 80)
        
        return {
            'total_runs': len(self.runs),
            'reproducibility_metrics': metrics,
            'attack_consistency': attack_consistency,
            'data_quality': all(not run['network_df'].empty for run in self.runs)
        }

def main():
    """Main function"""
    print("🚀 Starting A group experiment evaluation...")
    
    evaluator = GroupAEvaluator()
    
    if len(evaluator.runs) == 0:
        print("❌ No valid experiment data found")
        return
    
    # Generate report
    results = evaluator.generate_report()
    
    # Generate visualizations
    evaluator.generate_visualizations()
    
    # Save results to JSON
    with open('group_a_evaluation_results.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n💾 Detailed results saved to: group_a_evaluation_results.json")
    print(f"📊 Results saved to: evaluation_outputs/")

if __name__ == "__main__":
    main()
