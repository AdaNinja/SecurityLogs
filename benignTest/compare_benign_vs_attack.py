#!/usr/bin/env python3
"""
Comparison Analysis Script
Compares benign activities vs attack activities to identify distinguishing features
"""

import os
import re
import json
from datetime import datetime
from collections import Counter

class BenignVsAttackAnalyzer:
    def __init__(self):
        self.benign_data = {}
        self.attack_data = {}
        
    def analyze_benign_data(self):
        """Analyze benign activity data"""
        print("🔍 Analyzing benign activity data...")
        
        # Use existing comprehensive analysis
        from comprehensive_log_analyzer import ComprehensiveLogAnalyzer
        analyzer = ComprehensiveLogAnalyzer()
        report = analyzer.generate_comprehensive_report()
        
        self.benign_data = {
            "pcap_analysis": report["pcap_analysis"],
            "consistency": report["consistency"],
            "quality_assessment": report["quality_assessment"]
        }
        
        return self.benign_data
    
    def analyze_attack_data(self, attack_dir="attack_test"):
        """Analyze attack simulation data"""
        print("🔍 Analyzing attack simulation data...")
        
        if not os.path.exists(attack_dir):
            print(f"❌ Attack directory {attack_dir} not found")
            return None
        
        attack_analysis = {}
        
        # Analyze each attack type
        attack_types = ["slow_http", "get_flood", "bypass"]
        
        for attack_type in attack_types:
            attack_path = os.path.join(attack_dir, attack_type)
            if os.path.exists(attack_path):
                pcap_file = os.path.join(attack_path, "attack_traffic.pcap")
                if os.path.exists(pcap_file):
                    analysis = self.analyze_attack_pcap(pcap_file, attack_type)
                    attack_analysis[attack_type] = analysis
        
        self.attack_data = attack_analysis
        return self.attack_data
    
    def analyze_attack_pcap(self, pcap_file, attack_type):
        """Analyze attack PCAP file"""
        try:
            # Convert pcap to readable format
            output_file = pcap_file.replace('.pcap', '_readable.txt')
            cmd = f"tcpdump -r {pcap_file} -A -l > {output_file}"
            os.system(cmd)
            
            # Analyze the readable file
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            lines = content.split('\n')
            
            # Basic statistics
            total_lines = len(lines)
            non_empty_lines = len([line for line in lines if line.strip()])
            
            # Protocol analysis
            tcp_packets = len([line for line in lines if 'proto TCP' in line])
            udp_packets = len([line for line in lines if 'proto UDP' in line])
            
            # Port analysis
            port_pattern = r'\.(\d{1,5}):'
            all_ports = re.findall(port_pattern, content)
            port_counter = Counter(all_ports)
            top_ports = port_counter.most_common(10)
            
            # IP analysis
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            all_ips = re.findall(ip_pattern, content)
            ip_counter = Counter(all_ips)
            top_ips = ip_counter.most_common(10)
            
            # Direction analysis
            in_packets = len([line for line in lines if 'In ' in line])
            out_packets = len([line for line in lines if 'Out ' in line])
            
            # Time analysis
            timestamp_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)'
            timestamps = re.findall(timestamp_pattern, content)
            
            return {
                "attack_type": attack_type,
                "file_info": {
                    "total_lines": total_lines,
                    "non_empty_lines": non_empty_lines,
                    "file_path": pcap_file
                },
                "protocol_analysis": {
                    "tcp_packets": tcp_packets,
                    "udp_packets": udp_packets,
                    "tcp_percentage": tcp_packets / non_empty_lines * 100 if non_empty_lines > 0 else 0,
                    "udp_percentage": udp_packets / non_empty_lines * 100 if non_empty_lines > 0 else 0
                },
                "port_analysis": {
                    "total_unique_ports": len(set(all_ports)),
                    "top_ports": top_ports
                },
                "ip_analysis": {
                    "total_unique_ips": len(set(all_ips)),
                    "top_ips": top_ips
                },
                "direction_analysis": {
                    "incoming_packets": in_packets,
                    "outgoing_packets": out_packets,
                    "in_percentage": in_packets / non_empty_lines * 100 if non_empty_lines > 0 else 0,
                    "out_percentage": out_packets / non_empty_lines * 100 if non_empty_lines > 0 else 0
                },
                "time_analysis": {
                    "total_packets": len(timestamps)
                }
            }
            
        except Exception as e:
            print(f"❌ Error analyzing {pcap_file}: {e}")
            return None
    
    def compare_characteristics(self):
        """Compare benign vs attack characteristics"""
        print("🔄 Comparing benign vs attack characteristics...")
        
        comparison = {
            "packet_volume": {},
            "protocol_distribution": {},
            "port_usage": {},
            "ip_diversity": {},
            "direction_ratio": {},
            "temporal_patterns": {}
        }
        
        # Calculate average benign characteristics
        benign_avg = self.calculate_benign_averages()
        
        # Compare with each attack type
        for attack_type, attack_data in self.attack_data.items():
            if attack_data:
                comparison["packet_volume"][attack_type] = {
                    "benign_avg": benign_avg["packets"],
                    "attack": attack_data["time_analysis"]["total_packets"],
                    "ratio": attack_data["time_analysis"]["total_packets"] / benign_avg["packets"] if benign_avg["packets"] > 0 else 0
                }
                
                comparison["protocol_distribution"][attack_type] = {
                    "benign_tcp": benign_avg["tcp_percentage"],
                    "attack_tcp": attack_data["protocol_analysis"]["tcp_percentage"],
                    "difference": attack_data["protocol_analysis"]["tcp_percentage"] - benign_avg["tcp_percentage"]
                }
                
                comparison["port_usage"][attack_type] = {
                    "benign_ports": benign_avg["unique_ports"],
                    "attack_ports": attack_data["port_analysis"]["total_unique_ports"],
                    "difference": attack_data["port_analysis"]["total_unique_ports"] - benign_avg["unique_ports"]
                }
                
                comparison["ip_diversity"][attack_type] = {
                    "benign_ips": benign_avg["unique_ips"],
                    "attack_ips": attack_data["ip_analysis"]["total_unique_ips"],
                    "difference": attack_data["ip_analysis"]["total_unique_ips"] - benign_avg["unique_ips"]
                }
        
        return comparison
    
    def calculate_benign_averages(self):
        """Calculate average characteristics from benign data"""
        total_packets = 0
        total_tcp_percentage = 0
        total_unique_ports = 0
        total_unique_ips = 0
        count = 0
        
        for round_name, round_data in self.benign_data["pcap_analysis"].items():
            for victim, victim_data in round_data.items():
                if "time_analysis" in victim_data:
                    total_packets += victim_data["time_analysis"]["total_packets"]
                    total_tcp_percentage += victim_data["protocol_analysis"]["tcp_percentage"]
                    total_unique_ports += victim_data["port_analysis"]["total_unique_ports"]
                    total_unique_ips += victim_data["ip_analysis"]["total_unique_ips"]
                    count += 1
        
        if count > 0:
            return {
                "packets": total_packets / count,
                "tcp_percentage": total_tcp_percentage / count,
                "unique_ports": total_unique_ports / count,
                "unique_ips": total_unique_ips / count
            }
        else:
            return {"packets": 0, "tcp_percentage": 0, "unique_ports": 0, "unique_ips": 0}
    
    def generate_comparison_report(self):
        """Generate comprehensive comparison report"""
        print("📋 Generating comparison report...")
        
        # Analyze both datasets
        self.analyze_benign_data()
        self.analyze_attack_data()
        
        # Compare characteristics
        comparison = self.compare_characteristics()
        
        # Generate insights
        insights = self.generate_insights(comparison)
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "benign_data_summary": self.benign_data,
            "attack_data_summary": self.attack_data,
            "comparison": comparison,
            "insights": insights,
            "recommendations": self.generate_recommendations(comparison, insights)
        }
        
        return report
    
    def generate_insights(self, comparison):
        """Generate insights from comparison"""
        insights = []
        
        for attack_type in comparison["packet_volume"]:
            packet_ratio = comparison["packet_volume"][attack_type]["ratio"]
            
            if packet_ratio > 2.0:
                insights.append(f"🚨 {attack_type.upper()} attack shows {packet_ratio:.1f}x higher packet volume than benign traffic")
            elif packet_ratio > 1.5:
                insights.append(f"⚠️ {attack_type.upper()} attack shows {packet_ratio:.1f}x higher packet volume than benign traffic")
            
            tcp_diff = comparison["protocol_distribution"][attack_type]["difference"]
            if abs(tcp_diff) > 10:
                insights.append(f"📊 {attack_type.upper()} attack shows {tcp_diff:+.1f}% difference in TCP usage")
        
        return insights
    
    def generate_recommendations(self, comparison, insights):
        """Generate recommendations based on comparison"""
        recommendations = []
        
        if len(insights) > 0:
            recommendations.append("🎯 Attack patterns are distinguishable from benign traffic")
            recommendations.append("🔍 Consider implementing anomaly detection based on packet volume ratios")
            recommendations.append("📈 Monitor TCP protocol distribution for unusual patterns")
        else:
            recommendations.append("⚠️ Attack patterns are similar to benign traffic - need more sophisticated detection")
        
        recommendations.append("🛡️ Implement rate limiting based on packet volume thresholds")
        recommendations.append("🔍 Use machine learning to detect subtle attack patterns")
        
        return recommendations
    
    def print_comparison_summary(self, report):
        """Print comparison summary"""
        print("\n" + "="*80)
        print("🔍 BENIGN vs ATTACK COMPARISON SUMMARY")
        print("="*80)
        
        print(f"\n📊 BENIGN TRAFFIC AVERAGES:")
        benign_avg = self.calculate_benign_averages()
        print(f"   📦 Average packets per round: {benign_avg['packets']:.0f}")
        print(f"   🔗 Average TCP percentage: {benign_avg['tcp_percentage']:.1f}%")
        print(f"   🔌 Average unique ports: {benign_avg['unique_ports']:.0f}")
        print(f"   🌐 Average unique IPs: {benign_avg['unique_ips']:.0f}")
        
        print(f"\n🎯 ATTACK PATTERN ANALYSIS:")
        for attack_type in report["comparison"]["packet_volume"]:
            packet_ratio = report["comparison"]["packet_volume"][attack_type]["ratio"]
            tcp_diff = report["comparison"]["protocol_distribution"][attack_type]["difference"]
            
            print(f"   🚀 {attack_type.upper()}:")
            print(f"     📦 Packet volume ratio: {packet_ratio:.1f}x")
            print(f"     🔗 TCP usage difference: {tcp_diff:+.1f}%")
        
        if report["insights"]:
            print(f"\n💡 KEY INSIGHTS:")
            for insight in report["insights"]:
                print(f"   {insight}")
        
        print(f"\n🛡️ RECOMMENDATIONS:")
        for rec in report["recommendations"]:
            print(f"   {rec}")
        
        print("="*80)
    
    def save_report(self, report, filename="benign_vs_attack_comparison.json"):
        """Save comparison report"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"📄 Comparison report saved to {filename}")

def main():
    analyzer = BenignVsAttackAnalyzer()
    report = analyzer.generate_comparison_report()
    analyzer.print_comparison_summary(report)
    analyzer.save_report(report)

if __name__ == "__main__":
    main() 