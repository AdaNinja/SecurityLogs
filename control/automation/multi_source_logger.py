#!/usr/bin/env python3
"""
Multi-Source Log Collection and Analysis Script
Collects logs from multiple sources during SQL injection attacks
"""

import os
import json
import time
import subprocess
from datetime import datetime
from pathlib import Path

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
        """Analyze collected logs for attack patterns"""
        print("\n=== Analyzing Attack Patterns ===")
        
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'sql_injection_attempts': 0,
            'suspicious_requests': 0,
            'error_patterns': [],
            'attack_indicators': []
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
                            analysis['attack_indicators'].append({
                                'type': 'sql_injection',
                                'line': line.strip(),
                                'source': log_file.name
                            })
                        
                        # Look for suspicious patterns
                        if any(pattern in line.lower() for pattern in [
                            'python-requests', 'curl', 'wget'
                        ]):
                            analysis['suspicious_requests'] += 1
                            
            except Exception as e:
                print(f"[-] Error analyzing {log_file}: {e}")
        
        # Analyze error logs
        nginx_error_logs = list(self.logs_dir.glob("nginx_error_*.log"))
        for log_file in nginx_error_logs:
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        if 'sql' in line.lower() or 'database' in line.lower():
                            analysis['error_patterns'].append({
                                'type': 'sql_error',
                                'line': line.strip(),
                                'source': log_file.name
                            })
                            
            except Exception as e:
                print(f"[-] Error analyzing {log_file}: {e}")
        
        # Save analysis
        analysis_file = self.output_dir / f"attack_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(analysis_file, 'w') as f:
            json.dump(analysis, f, indent=2)
        
        print(f"[+] Attack analysis saved to: {analysis_file}")
        print(f"    SQL injection attempts: {analysis['sql_injection_attempts']}")
        print(f"    Suspicious requests: {analysis['suspicious_requests']}")
        print(f"    Error patterns: {len(analysis['error_patterns'])}")
        
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