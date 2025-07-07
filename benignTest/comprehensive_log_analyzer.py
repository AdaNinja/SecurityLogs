#!/usr/bin/env python3
"""
Comprehensive Log Analysis Script for Benign Activity Data
Integrates file structure analysis, content analysis, and consistency checking
"""

import os
import re
import json
from datetime import datetime
from collections import defaultdict, Counter

class ComprehensiveLogAnalyzer:
    def __init__(self, base_dir="."):
        self.base_dir = base_dir
        self.rounds = ["round1", "round2", "round3"]
        self.victims = ["victim1", "victim2"]
        
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
    
    def analyze_txt_content_detailed(self, txt_file_path):
        """Analyze a single txt file in detail"""
        if not os.path.exists(txt_file_path):
            return {"error": "File not found"}
            
        with open(txt_file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        lines = content.split('\n')
        
        # Basic statistics
        total_lines = len(lines)
        non_empty_lines = len([line for line in lines if line.strip()])
        
        # Extract timestamps and analyze time distribution
        timestamp_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)'
        timestamps = re.findall(timestamp_pattern, content)
        
        # Parse timestamps
        parsed_timestamps = []
        for ts in timestamps:
            try:
                parsed_ts = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S.%f')
                parsed_timestamps.append(parsed_ts)
            except:
                continue
        
        # Time analysis
        if parsed_timestamps:
            start_time = min(parsed_timestamps)
            end_time = max(parsed_timestamps)
            duration = (end_time - start_time).total_seconds()
        else:
            start_time = end_time = duration = None
        
        # Protocol analysis
        tcp_lines = [line for line in lines if 'proto TCP' in line]
        udp_lines = [line for line in lines if 'proto UDP' in line]
        
        # Port analysis
        port_pattern = r'\.(\d{1,5}):'
        all_ports = re.findall(port_pattern, content)
        port_counter = Counter(all_ports)
        top_ports = port_counter.most_common(10)
        
        # IP address analysis
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        all_ips = re.findall(ip_pattern, content)
        ip_counter = Counter(all_ips)
        top_ips = ip_counter.most_common(10)
        
        # Domain analysis
        domain_pattern = r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        all_domains = re.findall(domain_pattern, content)
        # Filter out local addresses
        external_domains = [d for d in all_domains if '.' in d and not d.startswith('127.') and not d.startswith('172.') and not d.startswith('192.168.')]
        domain_counter = Counter(external_domains)
        top_domains = domain_counter.most_common(10)
        
        # TCP flag analysis
        tcp_flags = []
        for line in tcp_lines:
            if 'Flags [' in line:
                flag_match = re.search(r'Flags \[([^\]]+)\]', line)
                if flag_match:
                    tcp_flags.append(flag_match.group(1))
        flag_counter = Counter(tcp_flags)
        
        # Packet size analysis
        size_pattern = r'length (\d+)'
        packet_sizes = re.findall(size_pattern, content)
        packet_sizes = [int(size) for size in packet_sizes if size.isdigit()]
        
        # Direction analysis (In/Out)
        in_packets = len([line for line in lines if 'In ' in line])
        out_packets = len([line for line in lines if 'Out ' in line])
        
        # Connection analysis
        connections = defaultdict(int)
        for line in tcp_lines:
            if '>' in line:
                # Extract source and destination
                parts = line.split('>')
                if len(parts) >= 2:
                    src_part = parts[0].strip().split()[-1]
                    dst_part = parts[1].strip().split(':')[0]
                    connection = f"{src_part} -> {dst_part}"
                    connections[connection] += 1
        
        top_connections = sorted(connections.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            "file_info": {
                "total_lines": total_lines,
                "non_empty_lines": non_empty_lines,
                "file_path": txt_file_path
            },
            "time_analysis": {
                "start_time": start_time.isoformat() if start_time else None,
                "end_time": end_time.isoformat() if end_time else None,
                "duration_seconds": duration,
                "total_packets": len(timestamps)
            },
            "protocol_analysis": {
                "tcp_packets": len(tcp_lines),
                "udp_packets": len(udp_lines),
                "tcp_percentage": len(tcp_lines) / non_empty_lines * 100 if non_empty_lines > 0 else 0,
                "udp_percentage": len(udp_lines) / non_empty_lines * 100 if non_empty_lines > 0 else 0
            },
            "port_analysis": {
                "total_unique_ports": len(set(all_ports)),
                "top_ports": top_ports
            },
            "ip_analysis": {
                "total_unique_ips": len(set(all_ips)),
                "top_ips": top_ips
            },
            "domain_analysis": {
                "total_unique_domains": len(set(external_domains)),
                "top_domains": top_domains
            },
            "tcp_flags": {
                "flag_distribution": dict(flag_counter),
                "total_tcp_connections": len(tcp_lines)
            },
            "packet_analysis": {
                "total_packets_with_size": len(packet_sizes),
                "average_packet_size": sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0,
                "min_packet_size": min(packet_sizes) if packet_sizes else 0,
                "max_packet_size": max(packet_sizes) if packet_sizes else 0
            },
            "direction_analysis": {
                "incoming_packets": in_packets,
                "outgoing_packets": out_packets,
                "in_percentage": in_packets / non_empty_lines * 100 if non_empty_lines > 0 else 0,
                "out_percentage": out_packets / non_empty_lines * 100 if non_empty_lines > 0 else 0
            },
            "connection_analysis": {
                "total_unique_connections": len(connections),
                "top_connections": top_connections
            }
        }
    
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
    
    def check_consistency(self, pcap_data):
        """Check consistency between rounds"""
        print("🔄 Checking data consistency...")
        consistency_report = {}
        
        # Compare file sizes and packet counts
        for victim in self.victims:
            victim_data = {}
            for round_name in self.rounds:
                if victim in pcap_data[round_name] and "time_analysis" in pcap_data[round_name][victim]:
                    victim_data[round_name] = pcap_data[round_name][victim]["time_analysis"]["total_packets"]
                else:
                    victim_data[round_name] = 0
            
            # Calculate variance
            values = list(victim_data.values())
            if len(values) > 1:
                mean_val = sum(values) / len(values)
                variance = sum((x - mean_val) ** 2 for x in values) / len(values)
                consistency_report[victim] = {
                    "packet_counts": victim_data,
                    "mean": mean_val,
                    "variance": variance,
                    "consistency_score": 1 - (variance / (mean_val ** 2)) if mean_val > 0 else 0
                }
            else:
                consistency_report[victim] = {
                    "packet_counts": victim_data,
                    "consistency_score": 1.0
                }
                
        return consistency_report
    
    def assess_data_quality(self, structure, pcap_content, host_logs, consistency):
        """Assess overall data quality and identify issues"""
        print("📊 Assessing data quality...")
        
        issues = []
        warnings = []
        quality_score = 100
        
        # Check file structure issues
        for round_name, round_data in structure.items():
            if round_data.get("status") == "MISSING":
                issues.append(f"Round {round_name} directory is missing")
                quality_score -= 30
            else:
                for victim, victim_data in round_data.get("victims", {}).items():
                    if victim_data.get("status") == "MISSING":
                        issues.append(f"Round {round_name} {victim} directory is missing")
                        quality_score -= 20
                    elif not victim_data.get("pcap_analysis_exists"):
                        issues.append(f"Round {round_name} {victim} pcap_analysis directory is missing")
                        quality_score -= 15
                    elif not victim_data.get("txt_files"):
                        issues.append(f"Round {round_name} {victim} has no txt files")
                        quality_score -= 10
        
        # Check content quality
        for round_name in self.rounds:
            for victim in self.victims:
                if victim in pcap_content[round_name]:
                    analysis = pcap_content[round_name][victim]
                    if "time_analysis" in analysis:
                        duration = analysis["time_analysis"].get("duration_seconds", 0)
                        packets = analysis["time_analysis"].get("total_packets", 0)
                        
                        if duration < 10:
                            warnings.append(f"Round {round_name} {victim} duration too short ({duration:.1f}s)")
                            quality_score -= 5
                        
                        if packets < 100:
                            warnings.append(f"Round {round_name} {victim} packet count too low ({packets})")
                            quality_score -= 5
        
        # Check consistency
        for victim, victim_data in consistency.items():
            score = victim_data.get("consistency_score", 1.0)
            if score < 0.8:
                warnings.append(f"{victim} shows low consistency between rounds (score: {score:.2f})")
                quality_score -= 10
            elif score < 0.6:
                issues.append(f"{victim} shows very low consistency between rounds (score: {score:.2f})")
                quality_score -= 20
        
        return {
            "quality_score": max(0, quality_score),
            "issues": issues,
            "warnings": warnings,
            "status": "EXCELLENT" if quality_score >= 90 else "GOOD" if quality_score >= 70 else "FAIR" if quality_score >= 50 else "POOR"
        }
    
    def generate_comprehensive_report(self):
        """Generate a comprehensive analysis report"""
        print("📋 Generating comprehensive analysis report...")
        
        # Run all analyses
        structure = self.analyze_file_structure()
        pcap_content = {}
        
        for round_name in self.rounds:
            round_data = {}
            for victim in self.victims:
                txt_file = os.path.join(self.base_dir, round_name, victim, "pcap_analysis", f"{victim}_{round_name}_readable.txt")
                analysis = self.analyze_txt_content_detailed(txt_file)
                round_data[victim] = analysis
            pcap_content[round_name] = round_data
        
        host_logs = self.analyze_host_logs()
        consistency = self.check_consistency(pcap_content)
        quality_assessment = self.assess_data_quality(structure, pcap_content, host_logs, consistency)
        
        # Generate report
        report = {
            "timestamp": datetime.now().isoformat(),
            "quality_assessment": quality_assessment,
            "file_structure": structure,
            "pcap_analysis": pcap_content,
            "host_logs": host_logs,
            "consistency": consistency,
            "recommendations": self.generate_recommendations(quality_assessment)
        }
        
        return report
    
    def generate_recommendations(self, quality_assessment):
        """Generate recommendations based on quality assessment"""
        recommendations = []
        
        if quality_assessment["issues"]:
            recommendations.append("🚨 CRITICAL: Fix missing files and directories before proceeding")
        
        if quality_assessment["warnings"]:
            recommendations.append("⚠️ WARNING: Investigate consistency and quality issues")
        
        if quality_assessment["quality_score"] >= 90:
            recommendations.append("✅ EXCELLENT: Data quality is very high, ready for analysis")
        elif quality_assessment["quality_score"] >= 70:
            recommendations.append("✅ GOOD: Data quality is acceptable for analysis")
        elif quality_assessment["quality_score"] >= 50:
            recommendations.append("⚠️ FAIR: Data quality needs improvement before analysis")
        else:
            recommendations.append("❌ POOR: Data quality is insufficient for reliable analysis")
        
        recommendations.append("🔍 Consider running additional validation tests on specific log content")
        recommendations.append("📊 Verify that all expected network activities were captured")
        
        return recommendations
    
    def print_comprehensive_summary(self, report):
        """Print a comprehensive summary"""
        print("\n" + "="*80)
        print("📊 COMPREHENSIVE LOG ANALYSIS SUMMARY")
        print("="*80)
        
        # Quality assessment
        quality = report["quality_assessment"]
        print(f"\n🎯 OVERALL QUALITY ASSESSMENT:")
        print(f"   Quality Score: {quality['quality_score']}/100")
        print(f"   Status: {quality['status']}")
        
        if quality["issues"]:
            print(f"\n🚨 CRITICAL ISSUES ({len(quality['issues'])}):")
            for issue in quality["issues"]:
                print(f"   • {issue}")
        
        if quality["warnings"]:
            print(f"\n⚠️ WARNINGS ({len(quality['warnings'])}):")
            for warning in quality["warnings"]:
                print(f"   • {warning}")
        
        # Detailed analysis by round
        print(f"\n📊 DETAILED ANALYSIS BY ROUND:")
        for round_name in self.rounds:
            print(f"\n🔍 {round_name.upper()}:")
            print("-" * 50)
            
            for victim in self.victims:
                if victim in report["pcap_analysis"][round_name]:
                    analysis = report["pcap_analysis"][round_name][victim]
                    
                    if "error" in analysis:
                        print(f"   {victim}: {analysis['error']}")
                        continue
                    
                    print(f"   📡 {victim.upper()}:")
                    
                    # Time analysis
                    time_info = analysis.get("time_analysis", {})
                    if time_info.get("duration_seconds"):
                        print(f"     ⏱️  Duration: {time_info['duration_seconds']:.2f}s")
                        print(f"     📦 Total packets: {time_info['total_packets']}")
                    
                    # Protocol analysis
                    proto_info = analysis.get("protocol_analysis", {})
                    print(f"     🔗 TCP: {proto_info.get('tcp_packets', 0)} ({proto_info.get('tcp_percentage', 0):.1f}%)")
                    print(f"     🔗 UDP: {proto_info.get('udp_packets', 0)} ({proto_info.get('udp_percentage', 0):.1f}%)")
                    
                    # Top domains
                    domain_info = analysis.get("domain_analysis", {})
                    if domain_info.get("top_domains"):
                        domains = [d[0] for d in domain_info['top_domains'][:3]]
                        print(f"     🌐 Top domains: {', '.join(domains)}")
                    
                    # Direction
                    dir_info = analysis.get("direction_analysis", {})
                    print(f"     📥 In: {dir_info.get('incoming_packets', 0)} ({dir_info.get('in_percentage', 0):.1f}%)")
                    print(f"     📤 Out: {dir_info.get('outgoing_packets', 0)} ({dir_info.get('out_percentage', 0):.1f}%)")
        
        # Consistency analysis
        print(f"\n🔄 CONSISTENCY ANALYSIS:")
        print("-" * 50)
        for victim, data in report["consistency"].items():
            score = data.get("consistency_score", 0)
            counts = data.get("packet_counts", {})
            print(f"   📊 {victim.upper()}:")
            print(f"     📦 Packet counts: {list(counts.values())}")
            print(f"     📈 Consistency score: {score:.3f}")
            print(f"     📊 Status: {'✅ Good' if score >= 0.8 else '⚠️ Fair' if score >= 0.6 else '❌ Poor'}")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        print("-" * 50)
        for rec in report["recommendations"]:
            print(f"   {rec}")
        
        print("="*80)
    
    def save_report(self, report, filename="comprehensive_log_analysis.json"):
        """Save the comprehensive analysis report"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"📄 Comprehensive report saved to {filename}")

def main():
    analyzer = ComprehensiveLogAnalyzer()
    report = analyzer.generate_comprehensive_report()
    analyzer.print_comprehensive_summary(report)
    analyzer.save_report(report)

if __name__ == "__main__":
    main() 