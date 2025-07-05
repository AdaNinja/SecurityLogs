#!/usr/bin/env python3
# Macro Attack Visualization Tool
# Generates text-based visualizations and tables for analysis results

import json
import os
from datetime import datetime

class MacroAttackVisualizer:
    def __init__(self, report_file=None):
        """Initialize visualizer with analysis report"""
        if report_file is None:
            # Try to find the report file automatically
            script_dir = os.path.dirname(os.path.abspath(__file__))
            report_file = os.path.join(script_dir, "macro_attack_analysis_report.json")
            
            # If not found in script directory, try current directory
            if not os.path.exists(report_file):
                report_file = "macro_attack_analysis_report.json"
        
        self.report_file = report_file
        self.report = self._load_report()
    
    def _load_report(self):
        """Load the analysis report"""
        if os.path.exists(self.report_file):
            with open(self.report_file, 'r') as f:
                return json.load(f)
        else:
            print(f"Report file {self.report_file} not found.")
            print("Please run analysis_tool.py first to generate the analysis report.")
            print("Expected file: macro_attack_analysis_report.json")
            return None
    
    def generate_text_charts(self):
        """Generate text-based charts and visualizations"""
        if not self.report:
            return
        
        print("\n" + "="*80)
        print("MACRO ATTACK ANALYSIS VISUALIZATIONS")
        print("="*80)
        
        # File count comparison chart
        self._print_file_count_chart()
        
        # Detection indicators comparison
        self._print_detection_indicators_chart()
        
        # File size comparison
        self._print_file_size_chart()
        
        # Stealth level comparison
        self._print_stealth_level_chart()
        
        # Detailed file type analysis
        self._print_file_type_analysis()
        
        # Detection recommendations table
        self._print_recommendations_table()
    
    def _print_file_count_chart(self):
        """Print file count comparison chart"""
        print("\n📊 FILE COUNT COMPARISON")
        print("-" * 50)
        
        variants = list(self.report['summary'].keys())
        max_files = max(self.report['summary'][v]['total_files'] for v in variants)
        
        for variant in variants:
            count = self.report['summary'][variant]['total_files']
            bar_length = int((count / max_files) * 40) if max_files > 0 else 0
            bar = "█" * bar_length
            print(f"{variant.upper():<10} | {bar} {count:>3} files")
    
    def _print_detection_indicators_chart(self):
        """Print detection indicators comparison chart"""
        print("\n🔍 DETECTION INDICATORS COMPARISON")
        print("-" * 60)
        
        indicators = ['obfuscation', 'encryption', 'network', 'commands', 'persistence']
        variants = list(self.report['summary'].keys())
        
        # Header
        header = f"{'Indicator':<12}"
        for variant in variants:
            header += f" | {variant.upper():<8}"
        print(header)
        print("-" * len(header))
        
        # Data rows
        for indicator in indicators:
            row = f"{indicator:<12}"
            for variant in variants:
                count = self.report['summary'][variant]['detection_indicators'].get(indicator, 0)
                row += f" | {count:>8}"
            print(row)
    
    def _print_file_size_chart(self):
        """Print file size comparison chart"""
        print("\n📏 FILE SIZE COMPARISON (bytes)")
        print("-" * 50)
        
        variants = list(self.report['summary'].keys())
        max_size = max(self.report['summary'][v]['total_size'] for v in variants)
        
        for variant in variants:
            size = self.report['summary'][variant]['total_size']
            bar_length = int((size / max_size) * 40) if max_size > 0 else 0
            bar = "█" * bar_length
            print(f"{variant.upper():<10} | {bar} {size:>8,} bytes")
    
    def _print_stealth_level_chart(self):
        """Print stealth level comparison"""
        print("\n🕵️  STEALTH LEVEL ANALYSIS")
        print("-" * 50)
        
        stealth_levels = self.report['detection_analysis']['stealth_level']
        complexity_levels = self.report['detection_analysis']['complexity_level']
        
        for variant in stealth_levels.keys():
            stealth = stealth_levels[variant]
            complexity = complexity_levels[variant]
            evasion_count = self.report['detection_analysis']['evasion_techniques'][variant]
            
            print(f"{variant.upper():<10} | Stealth: {stealth:<6} | Complexity: {complexity:<6} | Evasion Techniques: {evasion_count}")
    
    def _print_file_type_analysis(self):
        """Print detailed file type analysis"""
        print("\n📁 FILE TYPE ANALYSIS")
        print("-" * 50)
        
        variants = list(self.report['summary'].keys())
        
        # Collect all file types
        all_types = set()
        for variant in variants:
            all_types.update(self.report['summary'][variant]['file_types'].keys())
        
        # Header
        header = f"{'File Type':<12}"
        for variant in variants:
            header += f" | {variant.upper():<8}"
        print(header)
        print("-" * len(header))
        
        # Data rows
        for file_type in sorted(all_types):
            row = f"{file_type:<12}"
            for variant in variants:
                count = self.report['summary'][variant]['file_types'].get(file_type, 0)
                row += f" | {count:>8}"
            print(row)
    
    def _print_recommendations_table(self):
        """Print detection recommendations table"""
        print("\n💡 DETECTION RECOMMENDATIONS")
        print("-" * 80)
        
        recommendations = self.report['recommendations']
        
        if not recommendations:
            print("No specific recommendations generated.")
            return
        
        for i, rec in enumerate(recommendations, 1):
            print(f"\n{i}. {rec['type'].upper()} - {rec['severity']} SEVERITY")
            print(f"   Description: {rec['description']}")
            print(f"   Recommendation: {rec['recommendation']}")
    
    def generate_detection_guide(self, output_file="detection_guide.md"):
        """Generate a markdown detection guide"""
        if not self.report:
            return
        
        guide = f"""# Macro Attack Detection Guide

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary

This guide provides detection strategies for macro attack variants based on analysis of {len(self.report['summary'])} different attack scenarios.

## Attack Variants Overview

"""
        
        for variant, data in self.report['summary'].items():
            guide += f"""
### {variant.upper()} Variant
- **Total Files**: {data['total_files']}
- **Total Size**: {data['total_size']:,} bytes
- **Total Lines**: {data['total_lines']:,}
- **Stealth Level**: {self.report['detection_analysis']['stealth_level'][variant]}
- **Complexity Level**: {self.report['detection_analysis']['complexity_level'][variant]}

"""
        
        guide += """
## Detection Indicators

### 1. File Volume Analysis
- **Simple Variant**: Low file count, easy to detect
- **Medium Variant**: Moderate file count, requires monitoring
- **Complex Variant**: High file count, may indicate sophisticated attack

### 2. Obfuscation Detection
- Look for Base64 encoded content
- Check for XOR encryption patterns
- Monitor for encoded/obfuscated file names

### 3. Encryption Indicators
- AES, DES, RSA encryption references
- Key files and initialization vectors
- Encrypted payload detection

### 4. Network Activity
- HTTP/HTTPS request patterns
- Network connection indicators
- External communication attempts

### 5. System Commands
- Command execution patterns
- System information gathering
- Process enumeration

### 6. Persistence Mechanisms
- Startup script modifications
- Service installations
- Registry modifications

## Detection Recommendations

"""
        
        for rec in self.report['recommendations']:
            guide += f"""
### {rec['type'].upper()} - {rec['severity']} Severity
**Description**: {rec['description']}

**Recommendation**: {rec['recommendation']}

"""
        
        guide += """
## Implementation Strategy

1. **Baseline Monitoring**: Establish normal file creation patterns
2. **Content Analysis**: Implement file content scanning for indicators
3. **Network Monitoring**: Track external connections and requests
4. **Process Monitoring**: Monitor command execution and system calls
5. **Persistence Detection**: Watch for startup modifications and service changes

## Tools and Techniques

- **File Analysis**: Use tools to detect obfuscation and encryption
- **Network Monitoring**: Implement IDS/IPS for network activity
- **Process Monitoring**: Use EDR solutions for command execution
- **Registry Monitoring**: Track registry modifications
- **Log Analysis**: Correlate events across multiple sources

## Response Procedures

1. **Immediate**: Isolate affected systems
2. **Investigation**: Analyze file contents and network traffic
3. **Containment**: Remove persistence mechanisms
4. **Recovery**: Restore from clean backups
5. **Lessons Learned**: Update detection rules and procedures
"""
        
        with open(output_file, 'w') as f:
            f.write(guide)
        
        print(f"Detection guide saved to {output_file}")
    
    def generate_csv_report(self, output_file="macro_attack_comparison.csv"):
        """Generate a CSV report for further analysis"""
        if not self.report:
            return
        
        csv_content = "Variant,Total_Files,Total_Size,Total_Lines,Obfuscation_Files,Encryption_Files,Network_Files,Command_Files,Persistence_Files,Stealth_Level,Complexity_Level,Evasion_Techniques\n"
        
        for variant, data in self.report['summary'].items():
            stealth = self.report['detection_analysis']['stealth_level'][variant]
            complexity = self.report['detection_analysis']['complexity_level'][variant]
            evasion = self.report['detection_analysis']['evasion_techniques'][variant]
            
            csv_content += f"{variant},{data['total_files']},{data['total_size']},{data['total_lines']},"
            csv_content += f"{data['detection_indicators'].get('obfuscation', 0)},"
            csv_content += f"{data['detection_indicators'].get('encryption', 0)},"
            csv_content += f"{data['detection_indicators'].get('network', 0)},"
            csv_content += f"{data['detection_indicators'].get('commands', 0)},"
            csv_content += f"{data['detection_indicators'].get('persistence', 0)},"
            csv_content += f"{stealth},{complexity},{evasion}\n"
        
        with open(output_file, 'w') as f:
            f.write(csv_content)
        
        print(f"CSV report saved to {output_file}")

def main():
    """Main function to run the visualizer"""
    print("Macro Attack Visualization Tool")
    print("Generating text-based visualizations...")
    
    # Initialize visualizer
    visualizer = MacroAttackVisualizer()
    
    # Generate visualizations
    visualizer.generate_text_charts()
    
    # Generate additional reports
    visualizer.generate_detection_guide()
    visualizer.generate_csv_report()
    
    print("\nVisualization complete! Check the generated files for detailed analysis.")

if __name__ == "__main__":
    main() 