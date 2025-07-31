#!/usr/bin/env python3
"""
Multi-Source Security Log Analyzer for RAS
Correlates data from multiple log sources to provide comprehensive security analysis
"""

import re
import json
import csv
import sys
import os
from datetime import datetime, timedelta
from collections import defaultdict
import argparse
from typing import Dict, List, Set, Tuple

class MultiSourceAnalyzer:
    def __init__(self):
        self.attack_events = []
        self.nginx_events = []
        self.user_events = []
        self.auditd_events = []
        self.correlation_results = []
        
    def parse_attack_log(self, attack_log_path: str) -> bool:
        """Parse attack script log to extract attack events"""
        if not os.path.exists(attack_log_path):
            print(f"Warning: Attack log not found: {attack_log_path}")
            return False
            
        print(f"[*] Parsing attack log: {attack_log_path}")
        
        with open(attack_log_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        # Extract attack events with timestamps
        attack_pattern = r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] Line (\d+): (\w+) - (.+)'
        matches = re.findall(attack_pattern, content)
        
        for timestamp, line_num, attack_type, description in matches:
            self.attack_events.append({
                'timestamp': timestamp,
                'line': int(line_num),
                'type': attack_type,
                'description': description,
                'source': 'attack_script'
            })
            
        print(f"[*] Extracted {len(self.attack_events)} attack events")
        return True
        
    def parse_nginx_log(self, nginx_log_path: str) -> bool:
        """Parse nginx detailed log to extract HTTP requests"""
        if not os.path.exists(nginx_log_path):
            print(f"Warning: Nginx log not found: {nginx_log_path}")
            return False
            
        print(f"[*] Parsing nginx log: {nginx_log_path}")
        
        with open(nginx_log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # Parse nginx detailed log format
                # Format: IP - - [timestamp] "method path protocol" status size "referer" "user-agent" "attack-id" "payload-id"
                match = re.search(r'(\S+) - - \[([^\]]+)\] "(\S+) (\S+) ([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)"', line)
                if match:
                    ip, timestamp, method, path, protocol, status, size, referer, user_agent, attack_id, payload_id = match.groups()
                    
                    self.nginx_events.append({
                        'timestamp': timestamp,
                        'ip': ip,
                        'method': method,
                        'path': path,
                        'status': int(status),
                        'size': int(size),
                        'user_agent': user_agent,
                        'attack_id': attack_id if attack_id != '-' else None,
                        'payload_id': payload_id if payload_id != '-' else None,
                        'source': 'nginx'
                    })
                    
        print(f"[*] Extracted {len(self.nginx_events)} nginx events")
        return True
        
    def parse_user_log(self, user_log_path: str) -> bool:
        """Parse user benign traffic log"""
        if not os.path.exists(user_log_path):
            print(f"Warning: User log not found: {user_log_path}")
            return False
            
        print(f"[*] Parsing user log: {user_log_path}")
        
        with open(user_log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # Extract benign request events
                if "Running benign iteration" in line:
                    match = re.search(r'Running benign iteration (\d+)', line)
                    if match:
                        iteration = int(match.group(1))
                        self.user_events.append({
                            'timestamp': datetime.now().strftime('%d/%b/%Y:%H:%M:%S +0000'),
                            'iteration': iteration,
                            'type': 'benign_request',
                            'source': 'user_script'
                        })
                        
        print(f"[*] Extracted {len(self.user_events)} user events")
        return True
        
    def parse_auditd_log(self, auditd_log_path: str) -> bool:
        """Parse auditd log to extract system call events"""
        if not os.path.exists(auditd_log_path):
            print(f"Warning: Auditd log not found: {auditd_log_path}")
            return False
            
        print(f"[*] Parsing auditd log: {auditd_log_path}")
        
        with open(auditd_log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # Parse auditd log line
                # Extract timestamp and key information
                timestamp_match = re.search(r'time->(\w+ \w+ \d+ \d+:\d+:\d+ \d+)', line)
                key_match = re.search(r'key="([^"]+)"', line)
                pid_match = re.search(r'pid=(\d+)', line)
                exe_match = re.search(r'exe="([^"]+)"', line)
                
                if timestamp_match and key_match:
                    self.auditd_events.append({
                        'timestamp': timestamp_match.group(1),
                        'key': key_match.group(1),
                        'pid': int(pid_match.group(1)) if pid_match else None,
                        'exe': exe_match.group(1) if exe_match else None,
                        'raw_line': line.strip(),
                        'source': 'auditd'
                    })
                    
        print(f"[*] Extracted {len(self.auditd_events)} auditd events")
        return True
        
    def correlate_events(self) -> List[Dict]:
        """Correlate events across all log sources"""
        print("[*] Correlating events across log sources...")
        
        correlations = []
        
        # Group events by time windows
        time_window = timedelta(seconds=5)  # 5-second correlation window
        
        # Create time-based event groups
        all_events = []
        
        # Add attack events
        for event in self.attack_events:
            try:
                dt = datetime.strptime(event['timestamp'], '%Y-%m-%d %H:%M:%S')
                all_events.append((dt, 'attack', event))
            except ValueError:
                continue
                
        # Add nginx events
        for event in self.nginx_events:
            try:
                dt = datetime.strptime(event['timestamp'], '%d/%b/%Y:%H:%M:%S +0000')
                all_events.append((dt, 'nginx', event))
            except ValueError:
                continue
                
        # Add user events
        for event in self.user_events:
            try:
                dt = datetime.strptime(event['timestamp'], '%d/%b/%Y:%H:%M:%S +0000')
                all_events.append((dt, 'user', event))
            except ValueError:
                continue
                
        # Add auditd events
        for event in self.auditd_events:
            try:
                dt = datetime.strptime(event['timestamp'], '%a %b %d %H:%M:%S %Y')
                all_events.append((dt, 'auditd', event))
            except ValueError:
                continue
                
        # Sort all events by timestamp
        all_events.sort(key=lambda x: x[0])
        
        # Group events by time windows
        current_window_start = None
        current_window_events = []
        
        for dt, source, event in all_events:
            if current_window_start is None:
                current_window_start = dt
                current_window_events = [(dt, source, event)]
            elif dt - current_window_start <= time_window:
                current_window_events.append((dt, source, event))
            else:
                # Process current window
                if len(current_window_events) > 1:  # Only correlate if multiple events
                    correlation = self._create_correlation(current_window_events)
                    if correlation:
                        correlations.append(correlation)
                        
                # Start new window
                current_window_start = dt
                current_window_events = [(dt, source, event)]
                
        # Process last window
        if len(current_window_events) > 1:
            correlation = self._create_correlation(current_window_events)
            if correlation:
                correlations.append(correlation)
                
        print(f"[*] Created {len(correlations)} event correlations")
        return correlations
        
    def _create_correlation(self, window_events: List[Tuple]) -> Dict:
        """Create a correlation entry for a time window"""
        correlation = {
            'window_start': window_events[0][0].isoformat(),
            'window_end': window_events[-1][0].isoformat(),
            'event_count': len(window_events),
            'sources': set(),
            'attack_events': [],
            'nginx_events': [],
            'user_events': [],
            'auditd_events': []
        }
        
        for dt, source, event in window_events:
            correlation['sources'].add(source)
            
            if source == 'attack':
                correlation['attack_events'].append(event)
            elif source == 'nginx':
                correlation['nginx_events'].append(event)
            elif source == 'user':
                correlation['user_events'].append(event)
            elif source == 'auditd':
                correlation['auditd_events'].append(event)
                
        # Convert set to list for JSON serialization
        correlation['sources'] = list(correlation['sources'])
        
        return correlation
        
    def generate_statistics(self) -> Dict:
        """Generate comprehensive statistics"""
        stats = {
            'total_events': {
                'attack': len(self.attack_events),
                'nginx': len(self.nginx_events),
                'user': len(self.user_events),
                'auditd': len(self.auditd_events)
            },
            'correlations': len(self.correlation_results),
            'attack_types': defaultdict(int),
            'nginx_status_codes': defaultdict(int),
            'auditd_keys': defaultdict(int),
            'time_distribution': defaultdict(int)
        }
        
        # Attack type statistics
        for event in self.attack_events:
            stats['attack_types'][event['type']] += 1
            
        # Nginx status code statistics
        for event in self.nginx_events:
            stats['nginx_status_codes'][event['status']] += 1
            
        # Auditd key statistics
        for event in self.auditd_events:
            stats['auditd_keys'][event['key']] += 1
            
        # Time distribution (by hour)
        for event in self.attack_events + self.nginx_events + self.user_events + self.auditd_events:
            try:
                if 'timestamp' in event:
                    if 'attack' in event.get('source', ''):
                        dt = datetime.strptime(event['timestamp'], '%Y-%m-%d %H:%M:%S')
                    elif 'nginx' in event.get('source', '') or 'user' in event.get('source', ''):
                        dt = datetime.strptime(event['timestamp'], '%d/%b/%Y:%H:%M:%S +0000')
                    else:  # auditd
                        dt = datetime.strptime(event['timestamp'], '%a %b %d %H:%M:%S %Y')
                    stats['time_distribution'][dt.hour] += 1
            except ValueError:
                continue
                
        return stats
        
    def generate_report(self, output_dir: str):
        """Generate comprehensive multi-source analysis report"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate statistics
        stats = self.generate_statistics()
        
        # Generate summary report
        summary_file = os.path.join(output_dir, 'multi_source_summary.txt')
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("MULTI-SOURCE SECURITY LOG ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Event counts
            f.write("EVENT COUNTS BY SOURCE:\n")
            f.write("-" * 30 + "\n")
            for source, count in stats['total_events'].items():
                f.write(f"{source.upper()}: {count}\n")
            f.write(f"Total Events: {sum(stats['total_events'].values())}\n\n")
            
            # Correlations
            f.write(f"EVENT CORRELATIONS: {stats['correlations']}\n\n")
            
            # Attack type breakdown
            f.write("ATTACK TYPE BREAKDOWN:\n")
            f.write("-" * 25 + "\n")
            for attack_type, count in sorted(stats['attack_types'].items(), key=lambda x: x[1], reverse=True):
                f.write(f"{attack_type}: {count}\n")
            f.write("\n")
            
            # Nginx status codes
            f.write("NGINX STATUS CODES:\n")
            f.write("-" * 20 + "\n")
            for status, count in sorted(stats['nginx_status_codes'].items(), key=lambda x: x[1], reverse=True):
                f.write(f"{status}: {count}\n")
            f.write("\n")
            
            # Auditd keys
            f.write("AUDITD EVENT KEYS:\n")
            f.write("-" * 20 + "\n")
            for key, count in sorted(stats['auditd_keys'].items(), key=lambda x: x[1], reverse=True):
                f.write(f"{key}: {count}\n")
            f.write("\n")
            
        # Generate correlation CSV
        correlation_file = os.path.join(output_dir, 'event_correlations.csv')
        with open(correlation_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Window_Start', 'Window_End', 'Event_Count', 'Sources', 'Attack_Events', 'Nginx_Events', 'User_Events', 'Auditd_Events'])
            
            for correlation in self.correlation_results:
                writer.writerow([
                    correlation['window_start'],
                    correlation['window_end'],
                    correlation['event_count'],
                    ','.join(correlation['sources']),
                    len(correlation['attack_events']),
                    len(correlation['nginx_events']),
                    len(correlation['user_events']),
                    len(correlation['auditd_events'])
                ])
                
        # Generate JSON report
        json_file = os.path.join(output_dir, 'multi_source_analysis.json')
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'statistics': stats,
            'correlations': self.correlation_results[:100]  # Limit to first 100 for file size
        }
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
            
        print(f"[*] Multi-source analysis report generated in: {output_dir}")
        print(f"  - Summary: {summary_file}")
        print(f"  - Correlations: {correlation_file}")
        print(f"  - JSON: {json_file}")
        
    def analyze(self, attack_log: str, nginx_log: str, user_log: str, auditd_log: str, output_dir: str):
        """Main analysis method"""
        print("[*] Starting multi-source security log analysis...")
        
        # Parse all log sources
        self.parse_attack_log(attack_log)
        self.parse_nginx_log(nginx_log)
        self.parse_user_log(user_log)
        self.parse_auditd_log(auditd_log)
        
        # Correlate events
        self.correlation_results = self.correlate_events()
        
        # Generate report
        self.generate_report(output_dir)
        
        print("[*] Multi-source analysis completed!")

def main():
    parser = argparse.ArgumentParser(description='Multi-Source Security Log Analyzer')
    parser.add_argument('--attack-log', required=True, help='Path to attack script log')
    parser.add_argument('--nginx-log', required=True, help='Path to nginx detailed log')
    parser.add_argument('--user-log', required=True, help='Path to user benign traffic log')
    parser.add_argument('--auditd-log', required=True, help='Path to auditd log')
    parser.add_argument('--output-dir', required=True, help='Output directory for analysis')
    
    args = parser.parse_args()
    
    analyzer = MultiSourceAnalyzer()
    analyzer.analyze(
        attack_log=args.attack_log,
        nginx_log=args.nginx_log,
        user_log=args.user_log,
        auditd_log=args.auditd_log,
        output_dir=args.output_dir
    )

if __name__ == '__main__':
    main() 