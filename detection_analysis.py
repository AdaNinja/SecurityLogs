#!/usr/bin/env python3
"""
Detection Quality Analysis Script
Analyzes how different complexity variants of attack scenarios affect detection accuracy, 
false positive rates, and investigation complexity.

This script evaluates how different complexity variants of attack scenarios
affect detection accuracy, false positive rates, and investigation complexity.
"""

import yaml
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from typing import Dict, List, Any
import argparse
import os

class DetectionAnalyzer:
    def __init__(self, scenarios_dir: str = "scenarios"):
        self.scenarios_dir = scenarios_dir
        self.results = {}
        
        self.complexity_presets = {
            "basic": {
                "name": "Basic Difficulty",
                "description": "Suitable for beginners and basic detection system testing",
                "background_activity_weight": 0.35,  # Based on Sommer & Paxson (2010) - noise impact
                "attack_stealth_weight": 0.25,       # Based on MITRE ATT&CK - basic technique complexity
                "evasion_technique_weight": 0.25,    # Based on Laskov et al. (2004) - evasion impact
                "noise_level_weight": 0.15,          # Based on Garcia-Teodoro et al. (2009) - environmental factors
                "max_score": 3.0
            },
            "intermediate": {
                "name": "Intermediate Difficulty", 
                "description": "Suitable for intermediate detection systems and security analysts",
                "background_activity_weight": 0.3,   # Reduced noise impact for intermediate systems
                "attack_stealth_weight": 0.35,       # Increased stealth complexity
                "evasion_technique_weight": 0.25,    # Maintained evasion importance
                "noise_level_weight": 0.1,           # Reduced environmental noise impact
                "max_score": 4.0
            },
            "advanced": {
                "name": "Advanced Difficulty",
                "description": "Suitable for advanced detection systems and threat hunters",
                "background_activity_weight": 0.25,  # Minimal noise impact for advanced systems
                "attack_stealth_weight": 0.4,        # High stealth complexity (primary factor)
                "evasion_technique_weight": 0.3,     # High evasion sophistication
                "noise_level_weight": 0.05,          # Minimal environmental impact
                "max_score": 5.0
            }
        }
        
    def load_scenario_configs(self) -> Dict[str, Any]:
        """Load all scenario configuration files"""
        scenarios = {}
        for scenario_name in os.listdir(self.scenarios_dir):
            scenario_path = os.path.join(self.scenarios_dir, scenario_name)
            if os.path.isdir(scenario_path):
                config_path = os.path.join(scenario_path, "scenario.yaml")
                if os.path.exists(config_path):
                    with open(config_path, 'r', encoding='utf-8') as f:
                        scenarios[scenario_name] = yaml.safe_load(f)
        return scenarios
    
    def analyze_variant_complexity(self, scenario_config: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze complexity characteristics of scenario variants"""
        analysis = {
            'scenario_name': scenario_config['name'],
            'variants': {}
        }
        
        for variant_name, variant_config in scenario_config['variants'].items():
            # Get complexity configuration
            complexity_config = self._get_complexity_config(variant_config)
            
            # Calculate complexity score
            complexity_score = self._calculate_complexity_score(variant_config, complexity_config)
            
            # Analyze background activity complexity
            background_complexity = self._analyze_background_activities(variant_config.get('background_activities', []))
            
            # Analyze attack characteristics
            attack_complexity = self._analyze_attack_complexity(variant_config.get('attack', {}))
            
            analysis['variants'][variant_name] = {
                'complexity_score': complexity_score,
                'complexity_config': complexity_config,
                'background_complexity': background_complexity,
                'attack_complexity': attack_complexity,
                'config': variant_config
            }
        
        return analysis
    
    def _get_complexity_config(self, variant_config: Dict[str, Any]) -> Dict[str, Any]:
        """Get complexity configuration"""
        # Check if there's custom complexity configuration
        if 'complexity_config' in variant_config:
            custom_config = variant_config['complexity_config']
            # Merge custom config with preset config
            preset_name = custom_config.get('preset', 'intermediate')
            preset = self.complexity_presets.get(preset_name, self.complexity_presets['intermediate'])
            
            # Allow overriding preset parameters
            for key, value in custom_config.items():
                if key != 'preset':
                    preset[key] = value
            
            return preset
        else:
            # Use preset configuration
            preset_name = variant_config.get('complexity', 'intermediate')
            return self.complexity_presets.get(preset_name, self.complexity_presets['intermediate'])
    
    def _calculate_complexity_score(self, variant_config: Dict[str, Any], complexity_config: Dict[str, Any]) -> float:
        """
        Calculate variant complexity score
        
        Formula:
        Complexity Score = (Background Score × Background Weight) + (Stealth Score × Stealth Weight) + 
                          (Evasion Score × Evasion Weight) + (Noise Score × Noise Weight)
        
        Score calculation methods:
        - Background Score: Number of activities × 0.5
        - Stealth Score: Stealth level (low=1, medium=2, high=3)
        - Evasion Score: Number of evasion techniques × 1
        - Noise Score: (Number of activities × Average intensity) / 2.0
        """
        score = 0.0
        
        # ==================== 1. Background Score Calculation ====================
        # Background Score = Number of activities × 0.5
        background_activities = variant_config.get('background_activities', [])
        background_score = len(background_activities) * 0.5
        background_weighted = background_score * complexity_config['background_activity_weight']
        score += background_weighted
        
        # ==================== 2. Stealth Score Calculation ====================
        # Stealth Score = Stealth level (low=1, medium=2, high=3)
        attack_config = variant_config.get('attack', {})
        stealth_map = {'low': 1, 'medium': 2, 'high': 3}
        stealth_score = stealth_map.get(attack_config.get('stealth_level', 'low'), 1)
        stealth_weighted = stealth_score * complexity_config['attack_stealth_weight']
        score += stealth_weighted
        
        # ==================== 3. Evasion Score Calculation ====================
        # Evasion Score = Number of evasion techniques × 1
        evasion_score = 0
        if 'evasion_techniques' in attack_config:
            evasion_score = len(attack_config['evasion_techniques']) * 1
        elif 'evasion' in attack_config:
            evasion_score = len(attack_config['evasion']) * 1
        evasion_weighted = evasion_score * complexity_config['evasion_technique_weight']
        score += evasion_weighted
        
        # ==================== 4. Noise Score Calculation ====================
        # Noise Score = (Number of activities × Average intensity) / 2.0
        noise_score = 1.0  # Default noise score
        if background_activities:
            # Calculate average intensity
            total_intensity = 0
            for activity in background_activities:
                intensity_map = {'minimal': 1, 'moderate': 2, 'high': 3}
                intensity = activity.get('intensity', 'moderate')
                total_intensity += intensity_map.get(intensity, 2)
            avg_intensity = total_intensity / len(background_activities)
            
            # Noise Score = (Number of activities × Average intensity) / 2.0
            noise_score = (len(background_activities) * avg_intensity) / 2.0
        
        noise_weighted = noise_score * complexity_config['noise_level_weight']
        score += noise_weighted
        
        # ==================== 5. Final Score Limitation ====================
        # Ensure score doesn't exceed maximum score limit
        final_score = min(score, complexity_config['max_score'])
        
        return final_score
    
    def _calculate_complexity_score_detailed(self, variant_config: Dict[str, Any], complexity_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate variant complexity score with detailed calculation process
        
        Returns:
        {
            'final_score': final score,
            'calculation_details': {
                'background': {'score': score, 'weight': weight, 'weighted': weighted score},
                'stealth': {'score': score, 'weight': weight, 'weighted': weighted score},
                'evasion': {'score': score, 'weight': weight, 'weighted': weighted score},
                'noise': {'score': score, 'weight': weight, 'weighted': weighted score}
            },
            'formula': 'detailed calculation formula'
        }
        """
        details = {}
        
        # ==================== 1. Background Score Calculation ====================
        background_activities = variant_config.get('background_activities', [])
        background_score = len(background_activities) * 0.5
        background_weight = complexity_config['background_activity_weight']
        background_weighted = background_score * background_weight
        
        details['background'] = {
            'score': background_score,
            'weight': background_weight,
            'weighted': background_weighted,
            'description': f"Background Score = {len(background_activities)} activities × 0.5 = {background_score}"
        }
        
        # ==================== 2. Stealth Score Calculation ====================
        attack_config = variant_config.get('attack', {})
        stealth_map = {'low': 1, 'medium': 2, 'high': 3}
        stealth_level = attack_config.get('stealth_level', 'low')
        stealth_score = stealth_map.get(stealth_level, 1)
        stealth_weight = complexity_config['attack_stealth_weight']
        stealth_weighted = stealth_score * stealth_weight
        
        details['stealth'] = {
            'score': stealth_score,
            'weight': stealth_weight,
            'weighted': stealth_weighted,
            'description': f"Stealth Score = {stealth_level} level = {stealth_score}"
        }
        
        # ==================== 3. Evasion Score Calculation ====================
        evasion_score = 0
        if 'evasion_techniques' in attack_config:
            evasion_count = len(attack_config['evasion_techniques'])
            evasion_score = evasion_count * 1
        elif 'evasion' in attack_config:
            evasion_count = len(attack_config['evasion'])
            evasion_score = evasion_count * 1
        
        evasion_weight = complexity_config['evasion_technique_weight']
        evasion_weighted = evasion_score * evasion_weight
        
        details['evasion'] = {
            'score': evasion_score,
            'weight': evasion_weight,
            'weighted': evasion_weighted,
            'description': f"Evasion Score = {evasion_count} techniques × 1 = {evasion_score}"
        }
        
        # ==================== 4. Noise Score Calculation ====================
        noise_score = 1.0
        if background_activities:
            total_intensity = 0
            for activity in background_activities:
                intensity_map = {'minimal': 1, 'moderate': 2, 'high': 3}
                intensity = activity.get('intensity', 'moderate')
                total_intensity += intensity_map.get(intensity, 2)
            avg_intensity = total_intensity / len(background_activities)
            noise_score = (len(background_activities) * avg_intensity) / 2.0
        
        noise_weight = complexity_config['noise_level_weight']
        noise_weighted = noise_score * noise_weight
        
        details['noise'] = {
            'score': noise_score,
            'weight': noise_weight,
            'weighted': noise_weighted,
            'description': f"Noise Score = ({len(background_activities)} activities × {avg_intensity:.1f} avg intensity) / 2.0 = {noise_score:.1f}"
        }
        
        # ==================== 5. Final Score Calculation ====================
        total_score = background_weighted + stealth_weighted + evasion_weighted + noise_weighted
        max_score = complexity_config['max_score']
        final_score = min(total_score, max_score)
        
        # Build detailed formula
        formula = f"""
        Complexity Score Calculation Process:
        
        1. Background Score: {background_score} × {background_weight} = {background_weighted:.2f}
        2. Stealth Score: {stealth_score} × {stealth_weight} = {stealth_weighted:.2f}
        3. Evasion Score: {evasion_score} × {evasion_weight} = {evasion_weighted:.2f}
        4. Noise Score: {noise_score:.1f} × {noise_weight} = {noise_weighted:.2f}
        
        Total Score: {background_weighted:.2f} + {stealth_weighted:.2f} + {evasion_weighted:.2f} + {noise_weighted:.2f} = {total_score:.2f}
        Final Score: min({total_score:.2f}, {max_score}) = {final_score:.2f}
        """
        
        return {
            'final_score': final_score,
            'calculation_details': details,
            'formula': formula
        }
    
    def _analyze_background_activities(self, activities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze background activity complexity"""
        if not activities:
            return {'total_activities': 0, 'intensity_score': 0, 'complexity_score': 0}
        
        total_activities = len(activities)
        intensity_scores = []
        
        for activity in activities:
            # Intensity score
            intensity_map = {'minimal': 1, 'moderate': 2, 'high': 3}
            intensity = activity.get('intensity', 'moderate')
            intensity_scores.append(intensity_map.get(intensity, 2))
        
        avg_intensity = sum(intensity_scores) / len(intensity_scores)
        
        # Background complexity score (same as in _calculate_complexity_score)
        background_complexity = total_activities * 0.5
        
        return {
            'total_activities': total_activities,
            'intensity_score': avg_intensity,
            'complexity_score': background_complexity
        }
    
    def _analyze_attack_complexity(self, attack_config: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze attack complexity"""
        complexity = {
            'stealth_level': 0,
            'evasion_techniques': 0,
            'command_complexity': 0
        }
        
        # Stealth level
        stealth_map = {'low': 1, 'medium': 2, 'high': 3}
        complexity['stealth_level'] = stealth_map.get(attack_config.get('stealth_level', 'low'), 1)
        
        # Number of evasion techniques
        if 'evasion_techniques' in attack_config:
            complexity['evasion_techniques'] = len(attack_config['evasion_techniques'])
        elif 'evasion' in attack_config:
            complexity['evasion_techniques'] = len(attack_config['evasion'])
        
        # Command complexity
        if 'commands' in attack_config:
            complexity['command_complexity'] = len(attack_config['commands'])
        
        return complexity
    
    def predict_detection_metrics(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Predict detection metrics"""
        predictions = {}
        
        for variant_name, variant_data in analysis['variants'].items():
            complexity_score = variant_data['complexity_score']
            background_complexity = variant_data['background_complexity']['complexity_score']
            max_score = variant_data['complexity_config']['max_score']
            
            # Normalize complexity score
            normalized_complexity = complexity_score / max_score
            
            # Predict false positive rate (higher complexity = lower false positive rate)
            false_positive_rate = max(0.05, 0.4 - (normalized_complexity * 0.35))
            
            # Predict detection time (higher complexity = longer detection time)
            detection_time_minutes = 1 + (normalized_complexity * 20)
            
            # Predict alert accuracy (higher complexity = lower accuracy)
            alert_accuracy = max(0.2, 0.9 - (normalized_complexity * 0.7))
            
            # Predict investigation complexity (higher complexity = more complex investigation)
            investigation_complexity = min(5.0, 1.0 + (normalized_complexity * 4.0))
            
            # Predict noise level (more background activities = higher noise)
            noise_level = min(5.0, 1.0 + (background_complexity * 0.4))
            
            predictions[variant_name] = {
                'false_positive_rate': false_positive_rate,
                'detection_time_minutes': detection_time_minutes,
                'alert_accuracy': alert_accuracy,
                'investigation_complexity': investigation_complexity,
                'noise_level': noise_level
            }
        
        return predictions
    
    def generate_comparison_report(self, scenarios: Dict[str, Any]) -> str:
        """Generate comparison report"""
        report = []
        report.append("# Attack Scenario Variant Detection Quality Analysis Report")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        all_predictions = {}
        
        for scenario_name, scenario_config in scenarios.items():
            report.append(f"## Scenario: {scenario_config['name']}")
            report.append(f"Description: {scenario_config['description']}")
            report.append("")
            
            # Analyze variants
            analysis = self.analyze_variant_complexity(scenario_config)
            predictions = self.predict_detection_metrics(analysis)
            all_predictions[scenario_name] = predictions
            
            report.append("### Variant Complexity Analysis")
            for variant_name, variant_data in analysis['variants'].items():
                complexity_config = variant_data['complexity_config']
                report.append(f"#### {variant_data['config']['name']}")
                report.append(f"- Complexity Score: {variant_data['complexity_score']:.2f}")
                report.append(f"- Complexity Configuration: {complexity_config['name']}")
                report.append(f"- Max Score: {complexity_config['max_score']:.1f}")
                report.append(f"- Background Activities: {variant_data['background_complexity']['total_activities']}")
                report.append(f"- Attack Stealth Level: {variant_data['attack_complexity']['stealth_level']}")
                report.append(f"- Evasion Techniques: {variant_data['attack_complexity']['evasion_techniques']}")
                report.append("")
            
            report.append("### Predicted Detection Metrics")
            for variant_name, metrics in predictions.items():
                variant_config = analysis['variants'][variant_name]['config']
                report.append(f"#### {variant_config['name']}")
                report.append(f"- False Positive Rate: {metrics['false_positive_rate']:.2%}")
                report.append(f"- Detection Time: {metrics['detection_time_minutes']:.1f} minutes")
                report.append(f"- Alert Accuracy: {metrics['alert_accuracy']:.2%}")
                report.append(f"- Investigation Complexity: {metrics['investigation_complexity']:.1f}/5.0")
                report.append("")
            
            report.append("---")
            report.append("")
        
        # Cross-scenario comparison
        report.append("## Cross-Scenario Comparison Analysis")
        report.append("")
        
        # Create comparison table
        comparison_data = []
        for scenario_name, predictions in all_predictions.items():
            for variant_name, metrics in predictions.items():
                comparison_data.append({
                    'Scenario': scenario_name,
                    'Variant': variant_name,
                    'False_Positive_Rate': metrics['false_positive_rate'],
                    'Detection_Time_Minutes': metrics['detection_time_minutes'],
                    'Alert_Accuracy': metrics['alert_accuracy'],
                    'Investigation_Complexity': metrics['investigation_complexity']
                })
        
        df = pd.DataFrame(comparison_data)
        report.append("### Detection Metrics Comparison Table")
        report.append(df.to_markdown(index=False))
        report.append("")
        
        return "\n".join(report)
    
    def create_visualizations(self, scenarios: Dict[str, Any], output_dir: str = "analysis_output"):
        """Create visualizations"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Collect all data
        all_data = []
        for scenario_name, scenario_config in scenarios.items():
            analysis = self.analyze_variant_complexity(scenario_config)
            predictions = self.predict_detection_metrics(analysis)
            
            for variant_name, metrics in predictions.items():
                variant_config = analysis['variants'][variant_name]['config']
                all_data.append({
                    'Scenario': scenario_name,
                    'Variant': variant_config['name'],
                    'Complexity': variant_config['complexity'],
                    'False_Positive_Rate': metrics['false_positive_rate'],
                    'Detection_Time': metrics['detection_time_minutes'],
                    'Alert_Accuracy': metrics['alert_accuracy'],
                    'Investigation_Complexity': metrics['investigation_complexity'],
                    'Noise_Level': metrics['noise_level']
                })
        
        df = pd.DataFrame(all_data)
        
        # Set font for better display
        plt.rcParams['font.size'] = 10
        
        # 1. Complexity vs Detection Metrics Scatter Plot
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('Attack Scenario Variant Complexity vs Detection Metrics', fontsize=16)
        
        # Complexity mapping
        complexity_map = {'low': 1, 'medium': 2, 'high': 3}
        df['Complexity_Score'] = df['Complexity'].map(complexity_map)
        
        # False Positive Rate
        axes[0, 0].scatter(df['Complexity_Score'], df['False_Positive_Rate'], alpha=0.7)
        axes[0, 0].set_xlabel('Complexity Level')
        axes[0, 0].set_ylabel('False Positive Rate')
        axes[0, 0].set_title('Complexity vs False Positive Rate')
        
        # Detection Time
        axes[0, 1].scatter(df['Complexity_Score'], df['Detection_Time'], alpha=0.7)
        axes[0, 1].set_xlabel('Complexity Level')
        axes[0, 1].set_ylabel('Detection Time (Minutes)')
        axes[0, 1].set_title('Complexity vs Detection Time')
        
        # Alert Accuracy
        axes[1, 0].scatter(df['Complexity_Score'], df['Alert_Accuracy'], alpha=0.7)
        axes[1, 0].set_xlabel('Complexity Level')
        axes[1, 0].set_ylabel('Alert Accuracy')
        axes[1, 0].set_title('Complexity vs Alert Accuracy')
        
        # Investigation Complexity
        axes[1, 1].scatter(df['Complexity_Score'], df['Investigation_Complexity'], alpha=0.7)
        axes[1, 1].set_xlabel('Complexity Level')
        axes[1, 1].set_ylabel('Investigation Complexity')
        axes[1, 1].set_title('Complexity vs Investigation Complexity')
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'complexity_vs_detection_metrics.png'), dpi=300, bbox_inches='tight')
        plt.close()
        
        # 2. Heatmap
        plt.figure(figsize=(12, 8))
        correlation_matrix = df[['False_Positive_Rate', 'Detection_Time', 'Alert_Accuracy', 'Investigation_Complexity', 'Noise_Level']].corr()
        sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', center=0, 
                   square=True, fmt='.2f')
        plt.title('Detection Metrics Correlation Heatmap')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'detection_metrics_correlation.png'), dpi=300, bbox_inches='tight')
        plt.close()
        
        # 3. Boxplots by Scenario
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('Detection Metrics Distribution by Scenario', fontsize=16)
        
        metrics = ['False_Positive_Rate', 'Detection_Time', 'Alert_Accuracy', 'Investigation_Complexity']
        for i, metric in enumerate(metrics):
            row, col = i // 2, i % 2
            df.boxplot(column=metric, by='Scenario', ax=axes[row, col])
            axes[row, col].set_title(f'{metric} Distribution')
            axes[row, col].set_xlabel('')
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'scenario_metrics_distribution.png'), dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Visualizations saved to {output_dir} directory")

def main():
    """Main function to run the detection analysis"""
    parser = argparse.ArgumentParser(description='Analyze attack scenario complexity and detection quality')
    parser.add_argument('--scenarios-dir', default='scenarios', help='Directory containing scenario configurations')
    parser.add_argument('--output-dir', default='analysis_output', help='Output directory for reports and visualizations')
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = DetectionAnalyzer(args.scenarios_dir)
    
    # Load scenario configurations
    print("Loading scenario configurations...")
    scenarios = analyzer.load_scenario_configs()
    print(f"Found {len(scenarios)} scenario configurations")
    
    # Print complexity calculation formula
    print("\n" + "="*50)
    print("=== Complexity Calculation Formula ===")
    print("Complexity Score = (Background Score × Background Weight) + (Stealth Score × Stealth Weight) +")
    print("                   (Evasion Score × Evasion Weight) + (Noise Score × Noise Weight)")
    print()
    print("Score calculation methods:")
    print("- Background Score: Number of activities × 0.5")
    print("- Stealth Score: Stealth level (low=1, medium=2, high=3)")
    print("- Evasion Score: Number of evasion techniques × 1")
    print("- Noise Score: (Number of activities × Average intensity) / 2.0")
    print("="*50)
    
    # Analyze scenarios and generate report
    print("\nAnalyzing scenarios...")
    report = analyzer.generate_comparison_report(scenarios)
    
    # Save report
    os.makedirs(args.output_dir, exist_ok=True)
    report_path = os.path.join(args.output_dir, 'detection_analysis_report.md')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"Analysis report saved to: {report_path}")
    
    # Create visualizations
    print("Creating visualizations...")
    analyzer.create_visualizations(scenarios, args.output_dir)
    print(f"Visualizations saved to {args.output_dir} directory")
    
    print("Analysis completed!")

if __name__ == "__main__":
    main() 