#!/usr/bin/env python3
"""
Audit Log Analyzer for RAS Security Logs
Analyzes audit.log files to extract process execution, network connections, and file operations
Also includes attack analysis functionality
"""

import re
import json
import csv
import sys
import os
from datetime import datetime
from collections import defaultdict
import argparse

class AuditAnalyzer:
    def __init__(self, audit_log_path):
        self.audit_log_path = audit_log_path
        self.audit_events = []
        
    def parse_audit_line(self, line):
        """Parse a single audit log line"""
        if not line.strip():
            return None
            
        # Extract timestamp
        timestamp_match = re.search(r'time->(\w+ \w+ \d+ \d+:\d+:\d+ \d+)', line)
        if not timestamp_match:
            return None
            
        timestamp = timestamp_match.group(1)
        
        # Extract event type
        event_type_match = re.search(r'type=(\w+)', line)
        event_type = event_type_match.group(1) if event_type_match else "UNKNOWN"
        
        # Extract key information based on event type
        event_data = {
            'timestamp': timestamp,
            'event_type': event_type,
            'raw_line': line.strip()
        }
        
        # Extract common fields
        for field in ['pid', 'uid', 'gid', 'auid', 'euid', 'suid', 'fsuid', 'egid', 'sgid', 'fsgid']:
            match = re.search(f'{field}=(\d+)', line)
            if match:
                event_data[field] = int(match.group(1))
                
        # Extract executable path
        exe_match = re.search(r'exe="([^"]+)"', line)
        if exe_match:
            event_data['exe'] = exe_match.group(1)
            
        # Extract command
        comm_match = re.search(r'comm="([^"]+)"', line)
        if comm_match:
            event_data['comm'] = comm_match.group(1)
            
        # Extract syscall number
        syscall_match = re.search(r'syscall=(\d+)', line)
        if syscall_match:
            event_data['syscall'] = int(syscall_match.group(1))
            
        # Extract success status
        success_match = re.search(r'success=(\w+)', line)
        if success_match:
            event_data['success'] = success_match.group(1)
            
        # Extract key (rule identifier)
        key_match = re.search(r'key="([^"]+)"', line)
        if key_match:
            event_data['key'] = key_match.group(1)
            
        # Extract socket address for network connections
        saddr_match = re.search(r'saddr=([0-9a-f]+)', line)
        if saddr_match:
            event_data['saddr'] = saddr_match.group(1)
            
        return event_data
        
    def process_audit_log(self):
        """Process the entire audit log file"""
        if not os.path.exists(self.audit_log_path):
            print(f"Error: Audit log file not found: {self.audit_log_path}")
            return False
            
        print(f"[*] Processing audit log: {self.audit_log_path}")
        
        with open(self.audit_log_path, 'r', encoding='utf-8') as f:
            for line in f:
                event = self.parse_audit_line(line)
                if event:
                    self.audit_events.append(event)
                    
        print(f"[*] Processed {len(self.audit_events)} audit events")
        return True
        
    def get_statistics(self):
        """Get processing statistics"""
        if not self.audit_events:
            return {}
            
        stats = {
            'total_events': len(self.audit_events),
            'event_types': defaultdict(int),
            'keys': defaultdict(int),
            'syscalls': defaultdict(int),
            'executables': defaultdict(int),
            'users': defaultdict(int),
            'successful_events': 0,
            'failed_events': 0
        }
        
        for event in self.audit_events:
            stats['event_types'][event.get('event_type', 'UNKNOWN')] += 1
            
            if 'key' in event:
                stats['keys'][event['key']] += 1
                
            if 'syscall' in event:
                stats['syscalls'][event['syscall']] += 1
                
            if 'exe' in event:
                stats['executables'][event['exe']] += 1
                
            if 'uid' in event:
                stats['users'][event['uid']] += 1
                
            if event.get('success') == 'yes':
                stats['successful_events'] += 1
            elif event.get('success') == 'no':
                stats['failed_events'] += 1
                
        return stats
        
    def filter_events_by_key(self, key):
        """Filter events by audit rule key"""
        return [event for event in self.audit_events if event.get('key') == key]
        
    def export_to_csv(self, output_file, events=None):
        """Export audit events to CSV"""
        if events is None:
            events = self.audit_events
            
        if not events:
            print("No events to export")
            return False
            
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'timestamp', 'event_type', 'key', 'pid', 'uid', 'exe', 'comm',
                    'syscall', 'success', 'saddr', 'raw_line'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for event in events:
                    writer.writerow({
                        'timestamp': event.get('timestamp', ''),
                        'event_type': event.get('event_type', ''),
                        'key': event.get('key', ''),
                        'pid': event.get('pid', ''),
                        'uid': event.get('uid', ''),
                        'exe': event.get('exe', ''),
                        'comm': event.get('comm', ''),
                        'syscall': event.get('syscall', ''),
                        'success': event.get('success', ''),
                        'saddr': event.get('saddr', ''),
                        'raw_line': event.get('raw_line', '')
                    })
                    
            print(f"[*] Exported {len(events)} events to {output_file}")
            return True
            
        except Exception as e:
            print(f"Error exporting to CSV: {e}")
            return False
            
    def export_to_json(self, output_file, events=None):
        """Export audit events to JSON"""
        if events is None:
            events = self.audit_events
            
        if not events:
            print("No events to export")
            return False
            
        try:
            with open(output_file, 'w', encoding='utf-8') as jsonfile:
                json.dump(events, jsonfile, indent=2, ensure_ascii=False)
                
            print(f"[*] Exported {len(events)} events to {output_file}")
            return True
            
        except Exception as e:
            print(f"Error exporting to JSON: {e}")
            return False
            
    def print_summary(self):
        """Print processing summary"""
        stats = self.get_statistics()
        if not stats:
            print("No statistics available")
            return
            
        print("=" * 60)
        print("AUDIT LOG ANALYSIS SUMMARY")
        print("=" * 60)
        print(f"Total events processed: {stats['total_events']}")
        print(f"Successful events: {stats['successful_events']}")
        print(f"Failed events: {stats['failed_events']}")
        print()
        
        print("Top 5 Event Types:")
        for event_type, count in sorted(stats['event_types'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {event_type}: {count}")
        print()
        
        print("Top 5 Audit Keys:")
        for key, count in sorted(stats['keys'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {key}: {count}")
        print()
        
        print("Top 5 System Calls:")
        for syscall, count in sorted(stats['syscalls'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {syscall}: {count}")
        print()
        
        print("Top 5 Executables:")
        for exe, count in sorted(stats['executables'].items(), key=lambda x: x[1], reverse=True)[:5]:
            exe_short = exe[:50] + "..." if len(exe) > 50 else exe
            print(f"  {exe_short}: {count}")
        print()
        
        print("Top 5 Users (UID):")
        for uid, count in sorted(stats['users'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {uid}: {count}")
        print("=" * 60)

def main():
    parser = argparse.ArgumentParser(description='Audit Log Analyzer and Attack Analyzer for RAS Security Logs')
    
    # Create subparsers for different analysis modes
    subparsers = parser.add_subparsers(dest='command', help='Analysis command')
    
    # Audit log analysis
    audit_parser = subparsers.add_parser('audit', help='Analyze audit logs')
    audit_parser.add_argument('audit_log', help='Path to audit.log file')
    audit_parser.add_argument('--output-csv', help='Output CSV file path')
    audit_parser.add_argument('--output-json', help='Output JSON file path')
    audit_parser.add_argument('--summary-only', action='store_true', help='Only print summary, no export')
    audit_parser.add_argument('--filter-key', help='Filter events by audit key (e.g., proc_exec, net_connect)')
    
    # Attack analysis
    attack_parser = subparsers.add_parser('attack', help='Analyze attack logs')
    attack_parser.add_argument('--mode', choices=['normal', 'waf'], required=True, help='Analysis mode')
    attack_parser.add_argument('--attack-log', required=True, help='Path to attack script log file')
    attack_parser.add_argument('--nginx-log', required=True, help='Path to nginx access log file')
    attack_parser.add_argument('--modsec-log', help='Path to ModSecurity audit log file (WAF mode only)')
    attack_parser.add_argument('--output-dir', required=True, help='Output directory for analysis reports')
    
    args = parser.parse_args()
    
    if args.command == 'audit':
        # Audit log analysis
        analyzer = AuditAnalyzer(args.audit_log)
        
        # Process audit log
        if not analyzer.process_audit_log():
            sys.exit(1)
        
        # Filter events if requested
        events_to_export = analyzer.audit_events
        if args.filter_key:
            events_to_export = analyzer.filter_events_by_key(args.filter_key)
            print(f"[*] Filtered to {len(events_to_export)} events with key '{args.filter_key}'")
        
        # Print summary
        analyzer.print_summary()
        
        # Export if requested
        if not args.summary_only:
            if args.output_csv:
                analyzer.export_to_csv(args.output_csv, events_to_export)
            if args.output_json:
                analyzer.export_to_json(args.output_json, events_to_export)
            
            # Default export if no specific output specified
            if not args.output_csv and not args.output_json:
                analyzer.export_to_csv('audit_events.csv', events_to_export)
                analyzer.export_to_json('audit_events.json', events_to_export)
                
    elif args.command == 'attack':
        # Attack analysis
        analyzer = AttackAnalyzer(args.mode)
        
        # Analyze attack log
        analyzer.analyze_attack_log(args.attack_log)
        
        # Analyze nginx log
        nginx_traffic = analyzer.analyze_nginx_log(args.nginx_log)
        
        # Analyze ModSecurity log (WAF mode)
        if args.mode == 'waf' and args.modsec_log:
            waf_blocks = analyzer.analyze_modsecurity_log(args.modsec_log)
            
        # Generate statistics and report
        analyzer.generate_stats()
        analyzer.generate_report(args.output_dir)
        
        print(f"Attack analysis completed for {args.mode} mode")
        
    else:
        parser.print_help()
        sys.exit(1)

# Attack Analysis Class
class AttackAnalyzer:
    def __init__(self, mode="normal"):
        self.mode = mode
        self.attack_results = defaultdict(list)
        self.attack_stats = defaultdict(lambda: {
            'total': 0,
            'success': 0,
            'failed': 0,
            'blocked': 0,
            'details': []
        })
        
    def analyze_attack_log(self, log_file):
        """Analyze attack script log file"""
        if not os.path.exists(log_file):
            print(f"Warning: Attack log file not found: {log_file}")
            return
            
        print(f"Analyzing attack log: {log_file}")
        
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        lines = content.split('\n')
        current_attack = None
        
        for line in lines:
            # Match attack line
            match = re.search(r'Line (\d+): (\w+) - (.+)', line)
            if match:
                line_num, attack_type, description = match.groups()
                current_attack = {
                    'line': int(line_num),
                    'type': attack_type,
                    'description': description,
                    'status': 'unknown'
                }
                continue
                
            # Match result
            if current_attack:
                result_match = re.search(r'Result: HTTP (\d+) \(Expected: (\d+), WAF: (\w+)\)', line)
                if result_match:
                    http_code, expected, waf_mode = result_match.groups()
                    current_attack['http_code'] = int(http_code)
                    current_attack['expected'] = int(expected)
                    current_attack['waf_mode'] = waf_mode
                    
                    # Determine status
                    if self.mode == "waf" and waf_mode == "block" and http_code == "403":
                        current_attack['status'] = 'blocked'
                    elif http_code == expected:
                        current_attack['status'] = 'success'
                    else:
                        current_attack['status'] = 'failed'
                        
                    # Store attack result
                    self.attack_results[attack_type].append(current_attack)
                    current_attack = None
                    
    def analyze_nginx_log(self, nginx_log):
        """Analyze nginx access log for attack traffic"""
        if not os.path.exists(nginx_log):
            print(f"Warning: Nginx log file not found: {nginx_log}")
            return []
            
        print(f"Analyzing nginx log: {nginx_log}")
        
        attack_traffic = []
        with open(nginx_log, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # Parse nginx log line
                # Format: IP - - [timestamp] "method path protocol" status size "referer" "user-agent"
                match = re.search(r'(\S+) - - \[([^\]]+)\] "(\S+) (\S+) ([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)"', line)
                if match:
                    ip, timestamp, method, path, protocol, status, size, referer, user_agent = match.groups()
                    
                    # Check if this is attack traffic
                    if user_agent == "attacker":
                        attack_traffic.append({
                            'timestamp': timestamp,
                            'ip': ip,
                            'method': method,
                            'path': path,
                            'status': int(status),
                            'size': int(size),
                            'user_agent': user_agent
                        })
                        
        return attack_traffic
        
    def analyze_modsecurity_log(self, modsec_log):
        """Analyze ModSecurity audit log (WAF mode only)"""
        if not os.path.exists(modsec_log):
            print(f"Warning: ModSecurity log file not found: {modsec_log}")
            return []
            
        print(f"Analyzing ModSecurity log: {modsec_log}")
        
        waf_blocks = []
        with open(modsec_log, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                # Parse ModSecurity JSON log
                try:
                    data = json.loads(line)
                    if 'transaction' in data:
                        transaction = data['transaction']
                        if 'response' in transaction and transaction['response'].get('status') == 403:
                            waf_blocks.append({
                                'timestamp': transaction.get('time_stamp', ''),
                                'client_ip': transaction.get('client_ip', ''),
                                'request_method': transaction.get('request_method', ''),
                                'request_uri': transaction.get('request_uri', ''),
                                'rule_id': transaction.get('rule_id', ''),
                                'rule_msg': transaction.get('rule_msg', '')
                            })
                except json.JSONDecodeError:
                    continue
                    
        return waf_blocks
        
    def generate_stats(self):
        """Generate comprehensive attack statistics"""
        for attack_type, attacks in self.attack_results.items():
            stats = self.attack_stats[attack_type]
            stats['total'] = len(attacks)
            
            for attack in attacks:
                if attack['status'] == 'success':
                    stats['success'] += 1
                elif attack['status'] == 'blocked':
                    stats['blocked'] += 1
                else:
                    stats['failed'] += 1
                    
                stats['details'].append(attack)
                
    def generate_report(self, output_dir):
        """Generate comprehensive attack analysis report"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate summary report
        summary_file = os.path.join(output_dir, 'attack_summary.txt')
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write(f"ATTACK ANALYSIS REPORT - {self.mode.upper()} MODE\n")
            f.write("=" * 60 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Mode: {self.mode}\n\n")
            
            # Overall statistics
            total_attacks = sum(stats['total'] for stats in self.attack_stats.values())
            total_success = sum(stats['success'] for stats in self.attack_stats.values())
            total_failed = sum(stats['failed'] for stats in self.attack_stats.values())
            total_blocked = sum(stats['blocked'] for stats in self.attack_stats.values())
            
            f.write("OVERALL STATISTICS:\n")
            f.write("-" * 20 + "\n")
            f.write(f"Total Attacks: {total_attacks}\n")
            f.write(f"Successful: {total_success} ({total_success/total_attacks*100:.1f}%)\n")
            f.write(f"Failed: {total_failed} ({total_failed/total_attacks*100:.1f}%)\n")
            f.write(f"Blocked: {total_blocked} ({total_blocked/total_attacks*100:.1f}%)\n\n")
            
            # Attack type breakdown
            f.write("ATTACK TYPE BREAKDOWN:\n")
            f.write("-" * 25 + "\n")
            for attack_type, stats in self.attack_stats.items():
                if stats['total'] > 0:
                    f.write(f"{attack_type.upper()}:\n")
                    f.write(f"  Total: {stats['total']}\n")
                    f.write(f"  Success: {stats['success']} ({stats['success']/stats['total']*100:.1f}%)\n")
                    f.write(f"  Failed: {stats['failed']} ({stats['failed']/stats['total']*100:.1f}%)\n")
                    f.write(f"  Blocked: {stats['blocked']} ({stats['blocked']/stats['total']*100:.1f}%)\n\n")
                    
            # Detailed results
            f.write("DETAILED RESULTS:\n")
            f.write("-" * 18 + "\n")
            for attack_type, stats in self.attack_stats.items():
                if stats['total'] > 0:
                    f.write(f"\n{attack_type.upper()} ATTACKS:\n")
                    for attack in stats['details']:
                        f.write(f"  Line {attack['line']}: {attack['description']}\n")
                        f.write(f"    Status: {attack['status']}, HTTP: {attack.get('http_code', 'N/A')}\n")
                        
        # Generate CSV report
        csv_file = os.path.join(output_dir, 'attack_details.csv')
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Line', 'Type', 'Description', 'Status', 'HTTP_Code', 'Expected', 'WAF_Mode'])
            
            for attack_type, stats in self.attack_stats.items():
                for attack in stats['details']:
                    writer.writerow([
                        attack['line'],
                        attack['type'],
                        attack['description'],
                        attack['status'],
                        attack.get('http_code', ''),
                        attack.get('expected', ''),
                        attack.get('waf_mode', '')
                    ])
                    
        # Generate JSON report
        json_file = os.path.join(output_dir, 'attack_analysis.json')
        report_data = {
            'mode': self.mode,
            'timestamp': datetime.now().isoformat(),
            'overall_stats': {
                'total_attacks': total_attacks,
                'total_success': total_success,
                'total_failed': total_failed,
                'total_blocked': total_blocked
            },
            'attack_types': dict(self.attack_stats)
        }
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
            
        print(f"Attack analysis report generated in: {output_dir}")
        print(f"  - Summary: {summary_file}")
        print(f"  - CSV: {csv_file}")
        print(f"  - JSON: {json_file}")

def analyze_attacks(mode, attack_log, nginx_log, modsec_log=None, output_dir=None):
    """Convenience function to analyze attacks"""
    analyzer = AttackAnalyzer(mode)
    
    # Analyze attack log
    analyzer.analyze_attack_log(attack_log)
    
    # Analyze nginx log
    nginx_traffic = analyzer.analyze_nginx_log(nginx_log)
    
    # Analyze ModSecurity log (WAF mode)
    if mode == 'waf' and modsec_log:
        waf_blocks = analyzer.analyze_modsecurity_log(modsec_log)
        
    # Generate statistics and report
    analyzer.generate_stats()
    
    if output_dir:
        analyzer.generate_report(output_dir)
    
    return analyzer

if __name__ == '__main__':
    main() 