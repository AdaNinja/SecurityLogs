#!/usr/bin/env python3
"""
Multi-Source Log Collection and Analysis Script
Collects logs from multiple sources during SQL injection attacks
"""

import os
import json
import time
import subprocess
import re
from datetime import datetime
from pathlib import Path
import sys

# 添加MITRE映射器
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data_processing'))
from mitre_mapper import MITREMapper

class MultiSourceLogger:
    """Multi-source log collection and analysis"""
    
    def __init__(self, data_dir="../../data"):
        self.data_dir = Path(data_dir)
        self.logs_dir = self.data_dir / "logs"
        self.pcap_dir = self.data_dir / "pcap"
        self.output_dir = self.data_dir / "output"
        
        # Ensure directories exist
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.pcap_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.collection_log = []
        
        # 初始化MITRE映射器
        self.mitre_mapper = MITREMapper()
        
        # 网络连接跟踪
        self.network_connections = {}
        
    def extract_network_quintuple(self, log_line: str, source_type: str) -> dict:
        """从日志行中提取网络五元组信息"""
        quintuple = {
            "src_ip": "",
            "src_port": 0,
            "dst_ip": "",
            "dst_port": 0,
            "protocol": "",
            "connection_id": "",
            "connection_state": "ESTABLISHED",
            "session_duration": 0.0
        }
        
        # 从nginx访问日志提取
        if source_type == "nginx_access":
            # 格式: IP - - [timestamp] "method path protocol" status size "referer" "user-agent"
            match = re.match(r'^([^ ]+) - - \[([^\]]+)\] "([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)"', log_line)
            if match:
                ip, timestamp_str, request, status, size, referer, user_agent = match.groups()
                quintuple["src_ip"] = ip
                quintuple["dst_port"] = 80  # 默认HTTP端口
                quintuple["protocol"] = "HTTP"
                
                # 尝试从请求中提取端口
                if ':' in request:
                    port_match = re.search(r':(\d+)', request)
                    if port_match:
                        quintuple["dst_port"] = int(port_match.group(1))
                
                quintuple["connection_id"] = f"http_{ip}_0_0.0.0.0_{quintuple['dst_port']}"
        
        # 从tcpdump日志提取
        elif source_type == "tcpdump":
            # 格式: timestamp IP1.port > IP2.port: flags, seq, ack, win, length
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+):', log_line)
            if match:
                src_ip, src_port, dst_ip, dst_port = match.groups()
                quintuple["src_ip"] = src_ip
                quintuple["src_port"] = int(src_port)
                quintuple["dst_ip"] = dst_ip
                quintuple["dst_port"] = int(dst_port)
                quintuple["protocol"] = "TCP"
                quintuple["connection_id"] = f"tcp_{src_ip}_{src_port}_{dst_ip}_{dst_port}"
        
        return quintuple
    
    def analyze_mitre_attack(self, log_line: str, source_type: str, event_type: str = None) -> dict:
        """分析日志行并映射到MITRE ATT&CK技术"""
        details = {"raw": log_line}
        
        # 使用MITRE映射器
        mitre_mapping = self.mitre_mapper.map_attack_pattern(
            event_type or "unknown", 
            details,
            source_type
        )
        
        return mitre_mapping
    
    def collect_container_logs(self):
        """Collect logs from all containers"""
        print("=== Collecting Container Logs ===")
        
        containers = ["securitylogs-webapp", "securitylogs-tcpdump", "securitylogs-log-aggregator"]
        
        for container in containers:
            try:
                # Get container logs
                result = subprocess.run(
                    ["docker", "logs", container],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    log_file = self.logs_dir / f"{container}_logs.txt"
                    with open(log_file, 'w') as f:
                        f.write(result.stdout)
                        if result.stderr:
                            f.write("\n=== STDERR ===\n")
                            f.write(result.stderr)
                    
                    print(f"[+] Collected logs from {container}: {len(result.stdout)} chars")
                    self.collection_log.append({
                        'source': 'container_logs',
                        'container': container,
                        'timestamp': datetime.now().isoformat(),
                        'size': len(result.stdout),
                        'file': str(log_file)
                    })
                else:
                    print(f"[-] Failed to collect logs from {container}")
                    
            except Exception as e:
                print(f"[-] Error collecting logs from {container}: {e}")
    
    def collect_nginx_logs(self):
        """Collect nginx access and error logs"""
        print("\n=== Collecting Nginx Logs ===")
        
        nginx_logs = [
            ("access.log", "nginx_access"),
            ("error.log", "nginx_error")
        ]
        
        for log_file, prefix in nginx_logs:
            log_path = self.logs_dir / "nginx" / log_file
            if log_path.exists():
                try:
                    # Copy with timestamp
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_file = self.logs_dir / f"{prefix}_{timestamp}.log"
                    
                    with open(log_path, 'r') as src, open(output_file, 'w') as dst:
                        content = src.read()
                        dst.write(content)
                    
                    print(f"[+] Collected {log_file}: {len(content)} chars")
                    self.collection_log.append({
                        'source': 'nginx_logs',
                        'log_type': log_file,
                        'timestamp': datetime.now().isoformat(),
                        'size': len(content),
                        'file': str(output_file)
                    })
                    
                except Exception as e:
                    print(f"[-] Error collecting {log_file}: {e}")
            else:
                print(f"[-] {log_file} not found")
    
    def collect_pcap_files(self):
        """Collect and analyze PCAP files"""
        print("\n=== Collecting PCAP Files ===")
        
        pcap_files = list(self.pcap_dir.glob("*.pcap"))
        
        if not pcap_files:
            print("[-] No PCAP files found")
            return
        
        for pcap_file in pcap_files:
            try:
                # Get file info
                stat = pcap_file.stat()
                size_mb = stat.st_size / (1024 * 1024)
                
                print(f"[+] Found PCAP: {pcap_file.name} ({size_mb:.2f} MB)")
                
                # Basic PCAP analysis
                analysis_file = self.output_dir / f"{pcap_file.stem}_analysis.txt"
                
                # Use tcpdump to analyze PCAP
                result = subprocess.run([
                    "tcpdump", "-r", str(pcap_file), "-n", "-q"
                ], capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    with open(analysis_file, 'w') as f:
                        f.write(f"PCAP Analysis: {pcap_file.name}\n")
                        f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                        f.write(f"File size: {size_mb:.2f} MB\n")
                        f.write("=" * 50 + "\n")
                        f.write(result.stdout)
                    
                    print(f"    [+] Analysis saved to: {analysis_file}")
                    
                    self.collection_log.append({
                        'source': 'pcap_analysis',
                        'pcap_file': pcap_file.name,
                        'timestamp': datetime.now().isoformat(),
                        'size_mb': size_mb,
                        'analysis_file': str(analysis_file)
                    })
                    
            except Exception as e:
                print(f"[-] Error analyzing {pcap_file}: {e}")
    
    def collect_php_logs(self):
        """Collect PHP-FPM logs"""
        print("\n=== Collecting PHP Logs ===")
        
        php_log = self.logs_dir / "php7.4-fpm.log"
        if php_log.exists():
            try:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = self.logs_dir / f"php_fpm_{timestamp}.log"
                
                with open(php_log, 'r') as src, open(output_file, 'w') as dst:
                    content = src.read()
                    dst.write(content)
                
                print(f"[+] Collected PHP-FPM logs: {len(content)} chars")
                self.collection_log.append({
                    'source': 'php_logs',
                    'timestamp': datetime.now().isoformat(),
                    'size': len(content),
                    'file': str(output_file)
                })
                
            except Exception as e:
                print(f"[-] Error collecting PHP logs: {e}")
        else:
            print("[-] PHP-FPM log not found")
    
    def analyze_attack_patterns(self):
        """Analyze collected logs for attack patterns with enhanced analysis"""
        print("\n=== Analyzing Attack Patterns ===")
        
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'sql_injection_attempts': 0,
            'suspicious_requests': 0,
            'error_patterns': [],
            'attack_indicators': [],
            'network_connections': {},
            'mitre_techniques': {},
            'attack_chains': []
        }
        
        # Analyze nginx access logs
        nginx_logs = list(self.logs_dir.glob("nginx_access_*.log"))
        for log_file in nginx_logs:
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        # Look for SQL injection patterns
                        if any(pattern in line.lower() for pattern in [
                            'union', 'select', 'or 1=1', 'admin\'', '\'--'
                        ]):
                            analysis['sql_injection_attempts'] += 1
                            
                            # 提取网络五元组
                            quintuple = self.extract_network_quintuple(line, "nginx_access")
                            
                            # 分析MITRE ATT&CK
                            mitre_mapping = self.analyze_mitre_attack(line, "nginx_access", "sql_injection")
                            
                            attack_indicator = {
                                'type': 'sql_injection',
                                'line': line.strip(),
                                'timestamp': datetime.now().isoformat(),
                                'network_quintuple': quintuple,
                                'mitre_attack': mitre_mapping
                            }
                            
                            analysis['attack_indicators'].append(attack_indicator)
                            
                            # 统计MITRE技术
                            if mitre_mapping:
                                technique = mitre_mapping.get('technique', 'unknown')
                                if technique not in analysis['mitre_techniques']:
                                    analysis['mitre_techniques'][technique] = 0
                                analysis['mitre_techniques'][technique] += 1
                                
                                # 记录攻击链
                                if mitre_mapping.get('attack_chain'):
                                    analysis['attack_chains'].append(mitre_mapping['attack_chain'])
                            
                            # 记录网络连接
                            if quintuple['connection_id']:
                                if quintuple['connection_id'] not in analysis['network_connections']:
                                    analysis['network_connections'][quintuple['connection_id']] = {
                                        'quintuple': quintuple,
                                        'attack_count': 0,
                                        'first_seen': datetime.now().isoformat(),
                                        'last_seen': datetime.now().isoformat()
                                    }
                                analysis['network_connections'][quintuple['connection_id']]['attack_count'] += 1
                                analysis['network_connections'][quintuple['connection_id']]['last_seen'] = datetime.now().isoformat()
                        
                        # Look for other suspicious patterns
                        elif any(pattern in line.lower() for pattern in [
                            'admin', 'login', 'password', 'config', 'backup'
                        ]):
                            analysis['suspicious_requests'] += 1
                            
                            # 提取网络五元组
                            quintuple = self.extract_network_quintuple(line, "nginx_access")
                            
                            # 分析MITRE ATT&CK
                            mitre_mapping = self.analyze_mitre_attack(line, "nginx_access", "reconnaissance")
                            
                            attack_indicator = {
                                'type': 'suspicious_request',
                                'line': line.strip(),
                                'timestamp': datetime.now().isoformat(),
                                'network_quintuple': quintuple,
                                'mitre_attack': mitre_mapping
                            }
                            
                            analysis['attack_indicators'].append(attack_indicator)
                            
            except Exception as e:
                print(f"[-] Error analyzing {log_file}: {e}")
        
        # Analyze tcpdump logs for network patterns
        tcpdump_logs = list(self.logs_dir.glob("*tcpdump*"))
        for log_file in tcpdump_logs:
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        # 提取网络五元组
                        quintuple = self.extract_network_quintuple(line, "tcpdump")
                        
                        # 检查端口扫描模式
                        if any(pattern in line.lower() for pattern in [
                            'syn', 'fin', 'rst', 'port', 'scan'
                        ]):
                            # 分析MITRE ATT&CK
                            mitre_mapping = self.analyze_mitre_attack(line, "tcpdump", "network_scan")
                            
                            if mitre_mapping:
                                attack_indicator = {
                                    'type': 'port_scan',
                                    'line': line.strip(),
                                    'timestamp': datetime.now().isoformat(),
                                    'network_quintuple': quintuple,
                                    'mitre_attack': mitre_mapping
                                }
                                
                                analysis['attack_indicators'].append(attack_indicator)
                                
                                # 统计MITRE技术
                                technique = mitre_mapping.get('technique', 'unknown')
                                if technique not in analysis['mitre_techniques']:
                                    analysis['mitre_techniques'][technique] = 0
                                analysis['mitre_techniques'][technique] += 1
                            
            except Exception as e:
                print(f"[-] Error analyzing {log_file}: {e}")
        
        return analysis
    
    def generate_summary_report(self):
        """Generate a comprehensive summary report"""
        print("\n=== Generating Summary Report ===")
        
        report = {
            'collection_timestamp': datetime.now().isoformat(),
            'collection_summary': self.collection_log,
            'data_sources': {
                'container_logs': len([x for x in self.collection_log if x['source'] == 'container_logs']),
                'nginx_logs': len([x for x in self.collection_log if x['source'] == 'nginx_logs']),
                'php_logs': len([x for x in self.collection_log if x['source'] == 'php_logs']),
                'pcap_files': len([x for x in self.collection_log if x['source'] == 'pcap_analysis'])
            }
        }
        
        # Add attack analysis
        attack_analysis = self.analyze_attack_patterns()
        report['attack_analysis'] = attack_analysis
        
        # Save comprehensive report
        report_file = self.output_dir / f"comprehensive_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Comprehensive report saved to: {report_file}")
        
        # Print summary
        print("\n=== Collection Summary ===")
        print(f"Container logs collected: {report['data_sources']['container_logs']}")
        print(f"Nginx logs collected: {report['data_sources']['nginx_logs']}")
        print(f"PHP logs collected: {report['data_sources']['php_logs']}")
        print(f"PCAP files analyzed: {report['data_sources']['pcap_files']}")
        print(f"SQL injection attempts detected: {attack_analysis['sql_injection_attempts']}")
        
        return report

def main():
    """Main log collection orchestration"""
    print("🚀 Starting Multi-Source Log Collection")
    print("=" * 50)
    
    logger = MultiSourceLogger()
    
    try:
        # Collect from all sources
        logger.collect_container_logs()
        logger.collect_nginx_logs()
        logger.collect_php_logs()
        logger.collect_pcap_files()
        
        # Generate comprehensive report
        logger.generate_summary_report()
        
        print("\n✅ Multi-source log collection completed!")
        print("Check the following locations:")
        print("- Logs: data/logs/")
        print("- PCAP analysis: data/output/")
        print("- Reports: data/output/")
        
    except Exception as e:
        print(f"\n❌ Log collection failed: {e}")

if __name__ == "__main__":
    main() 