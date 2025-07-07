#!/usr/bin/env python3
"""
Log Analysis Script for Benign Activity Data
Analyzes the consistency and quality of three rounds of log data
"""

import os
import re
import json
from datetime import datetime
from collections import defaultdict, Counter

class LogAnalyzer:
    def __init__(self, base_dir="."):
        self.base_dir = base_dir
        self.rounds = ["round1", "round2", "round3"]
        self.victims = ["victim1", "victim2"]
        self.results = {}
        
    def analyze_file_structure(self):
        """Analyze the file structure and completeness"""
        print("🔍 Analyzing file structure...")
        structure_report = {}
        
        for round_name in self.rounds:
            round_dir = os.path.join(self.base_dir, round_name)
            if not os.path.exists(round_dir):
                structure_report[round_name] = {"status": "MISSING", "details": "Directory not found"}
                continue
                
            round_data = {"status": "EXISTS", "victims": {}, "host_logs": False}
            
            # Check victim directories
            for victim in self.victims:
                victim_dir = os.path.join(round_dir, victim)
                if os.path.exists(victim_dir):
                    files = os.listdir(victim_dir)
                    pcap_files = [f for f in files if f.endswith('.pcap')]
                    html_files = [f for f in files if f.endswith('.html')]
                    pcap_analysis_dir = os.path.join(victim_dir, "pcap_analysis")
                    
                    round_data["victims"][victim] = {
                        "pcap_count": len(pcap_files),
                        "html_count": len(html_files),
                        "pcap_analysis_exists": os.path.exists(pcap_analysis_dir),
                        "txt_files": []
                    }
                    
                    if os.path.exists(pcap_analysis_dir):
                        txt_files = [f for f in os.listdir(pcap_analysis_dir) if f.endswith('.txt')]
                        round_data["victims"][victim]["txt_files"] = txt_files
                else:
                    round_data["victims"][victim] = {"status": "MISSING"}
            
            # Check host_logs
            host_logs_dir = os.path.join(round_dir, "host_logs")
            if os.path.exists(host_logs_dir):
                host_files = os.listdir(host_logs_dir)
                round_data["host_logs"] = {
                    "exists": True,
                    "file_count": len(host_files),
                    "files": host_files
                }
            else:
                round_data["host_logs"] = {"exists": False}
                
            structure_report[round_name] = round_data
            
        return structure_report
    
    def analyze_pcap_content(self):
        """Analyze the content of pcap txt files"""
        print("📊 Analyzing PCAP content...")
        pcap_analysis = {}
        
        for round_name in self.rounds:
            round_data = {}
            for victim in self.victims:
                txt_file = os.path.join(self.base_dir, round_name, victim, "pcap_analysis", f"{victim}_{round_name}_readable.txt")
                
                if os.path.exists(txt_file):
                    with open(txt_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Extract basic statistics
                    lines = content.split('\n')
                    total_lines = len(lines)
                    
                    # Count packet types
                    tcp_packets = len([line for line in lines if 'proto TCP' in line])
                    udp_packets = len([line for line in lines if 'proto UDP' in line])
                    
                    # Extract unique IP addresses
                    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                    ips = re.findall(ip_pattern, content)
                    unique_ips = list(set(ips))
                    
                    # Extract unique ports
                    port_pattern = r'\.(\d{1,5}):'
                    ports = re.findall(port_pattern, content)
                    unique_ports = list(set(ports))
                    
                    # Extract domain names
                    domain_pattern = r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                    domains = re.findall(domain_pattern, content)
                    unique_domains = list(set([d for d in domains if '.' in d and not d.startswith('127.') and not d.startswith('172.')]))
                    
                    round_data[victim] = {
                        "total_lines": total_lines,
                        "tcp_packets": tcp_packets,
                        "udp_packets": udp_packets,
                        "unique_ips": len(unique_ips),
                        "unique_ports": len(unique_ports),
                        "unique_domains": len(unique_domains),
                        "sample_ips": unique_ips[:5],
                        "sample_domains": unique_domains[:5]
                    }
                else:
                    round_data[victim] = {"status": "FILE_NOT_FOUND"}
                    
            pcap_analysis[round_name] = round_data
            
        return pcap_analysis
    
    def analyze_host_logs(self):
        """Analyze host log files"""
        print("🖥️ Analyzing host logs...")
        host_analysis = {}
        
        for round_name in self.rounds:
            host_logs_dir = os.path.join(self.base_dir, round_name, "host_logs")
            if not os.path.exists(host_logs_dir):
                host_analysis[round_name] = {"status": "DIRECTORY_NOT_FOUND"}
                continue
                
            round_data = {}
            for log_file in os.listdir(host_logs_dir):
                if log_file.endswith('.log') or log_file == 'host_syslog':
                    file_path = os.path.join(host_logs_dir, log_file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        lines = content.split('\n')
                        round_data[log_file] = {
                            "size_bytes": len(content),
                            "line_count": len(lines),
                            "non_empty_lines": len([line for line in lines if line.strip()])
                        }
                    except Exception as e:
                        round_data[log_file] = {"error": str(e)}
                        
            host_analysis[round_name] = round_data
            
        return host_analysis
    
    def check_consistency(self):
        """Check consistency between rounds"""
        print("🔄 Checking data consistency...")
        consistency_report = {}
        
        # Get pcap analysis for comparison
        pcap_data = self.analyze_pcap_content()
        
        # Compare file sizes and packet counts
        for victim in self.victims:
            victim_data = {}
            for round_name in self.rounds:
                if victim in pcap_data[round_name] and "total_lines" in pcap_data[round_name][victim]:
                    victim_data[round_name] = pcap_data[round_name][victim]["total_lines"]
                else:
                    victim_data[round_name] = 0
            
            # Calculate variance
            values = list(victim_data.values())
            if len(values) > 1:
                mean_val = sum(values) / len(values)
                variance = sum((x - mean_val) ** 2 for x in values) / len(values)
                consistency_report[victim] = {
                    "line_counts": victim_data,
                    "mean": mean_val,
                    "variance": variance,
                    "consistency_score": 1 - (variance / (mean_val ** 2)) if mean_val > 0 else 0
                }
            else:
                consistency_report[victim] = {
                    "line_counts": victim_data,
                    "consistency_score": 1.0
                }
                
        return consistency_report
    
    def generate_summary_report(self):
        """Generate a comprehensive summary report"""
        print("📋 Generating summary report...")
        
        structure = self.analyze_file_structure()
        pcap_content = self.analyze_pcap_content()
        host_logs = self.analyze_host_logs()
        consistency = self.check_consistency()
        
        # Overall assessment
        issues = []
        warnings = []
        
        # Check for missing files
        for round_name, round_data in structure.items():
            if round_data.get("status") == "MISSING":
                issues.append(f"Round {round_name} directory is missing")
            else:
                for victim, victim_data in round_data.get("victims", {}).items():
                    if victim_data.get("status") == "MISSING":
                        issues.append(f"Round {round_name} {victim} directory is missing")
                    elif not victim_data.get("pcap_analysis_exists"):
                        issues.append(f"Round {round_name} {victim} pcap_analysis directory is missing")
                    elif not victim_data.get("txt_files"):
                        issues.append(f"Round {round_name} {victim} has no txt files")
        
        # Check consistency
        for victim, victim_data in consistency.items():
            if victim_data.get("consistency_score", 1.0) < 0.8:
                warnings.append(f"{victim} shows low consistency between rounds (score: {victim_data['consistency_score']:.2f})")
        
        # Generate report
        report = {
            "timestamp": datetime.now().isoformat(),
            "analysis_summary": {
                "total_rounds": len(self.rounds),
                "total_victims": len(self.victims),
                "issues_found": len(issues),
                "warnings": len(warnings)
            },
            "file_structure": structure,
            "pcap_analysis": pcap_content,
            "host_logs": host_logs,
            "consistency": consistency,
            "issues": issues,
            "warnings": warnings,
            "recommendations": self.generate_recommendations(issues, warnings)
        }
        
        return report
    
    def generate_recommendations(self, issues, warnings):
        """Generate recommendations based on issues and warnings"""
        recommendations = []
        
        if issues:
            recommendations.append("CRITICAL: Fix missing files and directories before proceeding with analysis")
        
        if warnings:
            recommendations.append("WARNING: Investigate consistency issues between rounds")
        
        if not issues and not warnings:
            recommendations.append("SUCCESS: All data appears to be consistent and complete")
        
        recommendations.append("Consider running additional validation tests on specific log content")
        recommendations.append("Verify that all expected network activities were captured")
        
        return recommendations
    
    def save_report(self, report, filename="log_analysis_report.json"):
        """Save the analysis report to a file"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"📄 Report saved to {filename}")
    
    def print_summary(self, report):
        """Print a human-readable summary"""
        print("\n" + "="*60)
        print("📊 LOG ANALYSIS SUMMARY")
        print("="*60)
        
        summary = report["analysis_summary"]
        print(f"Total rounds analyzed: {summary['total_rounds']}")
        print(f"Total victims: {summary['total_victims']}")
        print(f"Issues found: {summary['issues_found']}")
        print(f"Warnings: {summary['warnings']}")
        
        if report["issues"]:
            print("\n🚨 ISSUES:")
            for issue in report["issues"]:
                print(f"  - {issue}")
        
        if report["warnings"]:
            print("\n⚠️ WARNINGS:")
            for warning in report["warnings"]:
                print(f"  - {warning}")
        
        print("\n📈 CONSISTENCY SCORES:")
        for victim, data in report["consistency"].items():
            score = data.get("consistency_score", 0)
            print(f"  {victim}: {score:.3f}")
        
        print("\n💡 RECOMMENDATIONS:")
        for rec in report["recommendations"]:
            print(f"  - {rec}")
        
        print("="*60)

def main():
    analyzer = LogAnalyzer()
    report = analyzer.generate_summary_report()
    analyzer.save_report(report)
    analyzer.print_summary(report)

if __name__ == "__main__":
    main() 