#!/usr/bin/env python3
"""
Ground Truth Label Generator for RAS Security Logs
Efficiently generates labels from existing attack.log and nginx logs
"""

import re
import json
import csv
import sys
import os
from datetime import datetime
from collections import defaultdict
import argparse
from typing import Dict, List, Set, Tuple

class GTLabelGenerator:
    def __init__(self):
        self.attack_ips = set()
        self.attack_timestamps = []
        self.attack_details = []
        self.nginx_records = []
        self.labeled_records = []
        
    def extract_attack_info(self, attack_log_path: str) -> bool:
        """Extract attack information from attack.log"""
        if not os.path.exists(attack_log_path):
            print(f"Error: Attack log not found: {attack_log_path}")
            return False
            
        print(f"[*] Extracting attack info from: {attack_log_path}")
        
        with open(attack_log_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        # Extract container IP
        ip_match = re.search(r'Container IP: (\d+\.\d+\.\d+\.\d+)', content)
        if ip_match:
            attack_ip = ip_match.group(1)
            self.attack_ips.add(attack_ip)
            print(f"[*] Found attack IP: {attack_ip}")
            
        # Extract attack details from ===ATTACK_START=== blocks
        attack_blocks = re.findall(r'===ATTACK_START===\n(.*?)\n===ATTACK_END===', content, re.DOTALL)
        
        for block in attack_blocks:
            attack_info = {}
            
            # Extract key information
            payload_match = re.search(r'PAYLOAD_ID: (\d+)', block)
            attack_type_match = re.search(r'ATTACK_TYPE: (\w+)', block)
            timestamp_match = re.search(r'TIMESTAMP: ([^\n]+)', block)
            method_match = re.search(r'METHOD: (\w+)', block)
            path_match = re.search(r'PATH: ([^\n]+)', block)
            
            if payload_match and timestamp_match:
                attack_info = {
                    'payload_id': payload_match.group(1),
                    'attack_type': attack_type_match.group(1) if attack_type_match else 'unknown',
                    'timestamp': timestamp_match.group(1),
                    'method': method_match.group(1) if method_match else 'unknown',
                    'path': path_match.group(1) if path_match else 'unknown',
                    'source_ip': list(self.attack_ips)[0] if self.attack_ips else 'unknown'
                }
                
                self.attack_details.append(attack_info)
                self.attack_timestamps.append(attack_info['timestamp'])
                
        print(f"[*] Extracted {len(self.attack_details)} attack details")
        return True
        
    def parse_nginx_log(self, nginx_log_path: str) -> bool:
        """Parse nginx detailed log"""
        if not os.path.exists(nginx_log_path):
            print(f"Error: Nginx log not found: {nginx_log_path}")
            return False
            
        print(f"[*] Parsing nginx log: {nginx_log_path}")
        
        with open(nginx_log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                # Parse nginx detailed log format
                # Format: IP - - [timestamp] "method path protocol" status size "referer" "user-agent" "attack-id" "payload-id" "timestamp" "source-ip" "traffic-type" "attack-type"
                match = re.search(r'(\S+) - - \[([^\]]+)\] "(\S+) (\S+) ([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)"', line)
                if match:
                    groups = match.groups()
                    if len(groups) >= 14:
                        ip, timestamp, method, path, protocol, status, size, referer, user_agent, attack_id, payload_id, http_timestamp, source_ip, traffic_type = groups[:14]
                        attack_type = groups[14] if len(groups) > 14 else '-'
                        
                        self.nginx_records.append({
                            'line_num': line_num,
                            'timestamp': timestamp,
                            'ip': ip,
                            'method': method,
                            'path': path,
                            'status': int(status),
                            'size': int(size),
                            'user_agent': user_agent,
                            'attack_id': attack_id if attack_id != '-' else None,
                            'payload_id': payload_id if payload_id != '-' else None,
                            'http_timestamp': http_timestamp if http_timestamp != '-' else None,
                            'source_ip': source_ip if source_ip != '-' else None,
                            'traffic_type': traffic_type if traffic_type != '-' else None,
                            'attack_type': attack_type if attack_type != '-' else None,
                            'raw_line': line.strip()
                        })
                    
        print(f"[*] Parsed {len(self.nginx_records)} nginx records")
        return True
        
    def generate_labels(self) -> List[Dict]:
        """Generate ground truth labels for nginx records using attack.log TIMESTAMP and IP"""
        print("[*] Generating ground truth labels using attack.log TIMESTAMP and IP...")
        
        labeled_records = []
        
        # Create time-based attack mapping
        attack_time_map = {}
        for attack in self.attack_details:
            # Parse attack timestamp
            try:
                attack_time = datetime.strptime(attack['timestamp'], '%Y-%m-%dT%H:%M:%SZ')
                attack_time_map[attack_time] = {
                    'payload_id': attack['payload_id'],
                    'source_ip': attack['source_ip'],
                    'attack_type': attack['attack_type']
                }
            except ValueError:
                print(f"[WARNING] Could not parse attack timestamp: {attack['timestamp']}")
                continue
        
        print(f"[*] Created time-based attack mapping for {len(attack_time_map)} attacks")
        
        for record in self.nginx_records:
            # Initialize label as benign (default)
            gt_label = "benign"
            label_reason = "default_benign"
            
            # Method 1: Time + IP matching (±5 seconds)
            try:
                nginx_time = datetime.strptime(record['timestamp'], '%d/%b/%Y:%H:%M:%S +0000')
                
                for attack_time, attack_info in attack_time_map.items():
                    time_diff = abs((nginx_time - attack_time).total_seconds())
                    
                    if time_diff <= 5:  # 5-second window
                        if record['ip'] == attack_info['source_ip']:
                            gt_label = "attack"
                            label_reason = f"time_ip_match:payload_{attack_info['payload_id']}_at_{attack_time.strftime('%H:%M:%S')}"
                            break
                        elif record['source_ip'] == attack_info['source_ip']:
                            gt_label = "attack"
                            label_reason = f"time_source_ip_match:payload_{attack_info['payload_id']}_at_{attack_time.strftime('%H:%M:%S')}"
                            break
                            
            except ValueError:
                print(f"[WARNING] Could not parse nginx timestamp: {record['timestamp']}")
            
            # Method 2: IP matching (fallback)
            if gt_label == "benign":
                if record['ip'] in self.attack_ips:
                    gt_label = "attack"
                    label_reason = f"ip_match:{record['ip']}"
                elif record['source_ip'] in self.attack_ips:
                    gt_label = "attack"
                    label_reason = f"source_ip_match:{record['source_ip']}"
            
            # Add label information to record
            labeled_record = record.copy()
            labeled_record['gt_label'] = gt_label
            labeled_record['label_reason'] = label_reason
            
            labeled_records.append(labeled_record)
            
        print(f"[*] Generated labels for {len(labeled_records)} records")
        
        # Print label distribution
        label_counts = defaultdict(int)
        for record in labeled_records:
            label_counts[record['gt_label']] += 1
            
        print("[*] Label distribution:")
        for label, count in label_counts.items():
            percentage = (count / len(labeled_records)) * 100
            print(f"  {label}: {count} ({percentage:.1f}%)")
            
        return labeled_records
        
    def export_to_csv(self, output_file: str, records: List[Dict]) -> bool:
        """Export labeled records to CSV"""
        if not records:
            print("No records to export")
            return False
            
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'line_num', 'timestamp', 'ip', 'method', 'path', 'status', 'size',
                    'user_agent', 'attack_id', 'payload_id', 'http_timestamp',
                    'source_ip', 'traffic_type', 'attack_type', 'gt_label',
                    'label_reason'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for record in records:
                    writer.writerow({
                        'line_num': record.get('line_num', ''),
                        'timestamp': record.get('timestamp', ''),
                        'ip': record.get('ip', ''),
                        'method': record.get('method', ''),
                        'path': record.get('path', ''),
                        'status': record.get('status', ''),
                        'size': record.get('size', ''),
                        'user_agent': record.get('user_agent', ''),
                        'attack_id': record.get('attack_id', ''),
                        'payload_id': record.get('payload_id', ''),
                        'http_timestamp': record.get('http_timestamp', ''),
                        'source_ip': record.get('source_ip', ''),
                        'traffic_type': record.get('traffic_type', ''),
                        'attack_type': record.get('attack_type', ''),
                        'gt_label': record.get('gt_label', ''),
                        'label_reason': record.get('label_reason', '')
                    })
                    
            print(f"[*] Exported {len(records)} labeled records to {output_file}")
            return True
            
        except Exception as e:
            print(f"Error exporting to CSV: {e}")
            return False
            
    def export_to_json(self, output_file: str, records: List[Dict]) -> bool:
        """Export labeled records to JSON"""
        if not records:
            print("No records to export")
            return False
            
        try:
            # Prepare metadata
            metadata = {
                'generated_at': datetime.now().isoformat(),
                'total_records': len(records),
                'attack_ips': list(self.attack_ips),
                'attack_details': self.attack_details,
                'labeling_rules': [
                    "Time + IP matching (±5 seconds): nginx timestamp matches attack.log timestamp and IP matches → attack",
                    "IP matching: IP in attack_ips list → attack",
                    "Default: all other traffic → benign"
                ]
            }
            
            export_data = {
                'metadata': metadata,
                'records': records
            }
            
            with open(output_file, 'w', encoding='utf-8') as jsonfile:
                json.dump(export_data, jsonfile, indent=2, ensure_ascii=False)
                
            print(f"[*] Exported {len(records)} labeled records to {output_file}")
            return True
            
        except Exception as e:
            print(f"Error exporting to JSON: {e}")
            return False
            
    def generate_summary(self, output_dir: str):
        """Generate summary report"""
        os.makedirs(output_dir, exist_ok=True)
        
        summary_file = os.path.join(output_dir, 'gt_labeling_summary.txt')
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("GROUND TRUTH LABELING SUMMARY\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Attack information
            f.write("ATTACK INFORMATION:\n")
            f.write("-" * 20 + "\n")
            f.write(f"Attack IPs: {list(self.attack_ips)}\n")
            f.write(f"Attack details: {len(self.attack_details)} attacks\n")
            for attack in self.attack_details:
                f.write(f"  - Payload {attack['payload_id']}: {attack['attack_type']} at {attack['timestamp']}\n")
            f.write("\n")
            
            # Label distribution
            label_counts = defaultdict(int)
            for record in self.labeled_records:
                label_counts[record['gt_label']] += 1
                
            f.write("LABEL DISTRIBUTION:\n")
            f.write("-" * 20 + "\n")
            for label, count in sorted(label_counts.items()):
                percentage = (count / len(self.labeled_records)) * 100
                f.write(f"{label}: {count} ({percentage:.1f}%)\n")
            f.write("\n")
            
            # Labeling rules
            f.write("LABELING RULES USED:\n")
            f.write("-" * 20 + "\n")
            f.write("1. Time + IP matching (±5 seconds): nginx timestamp matches attack.log timestamp and IP matches → attack\n")
            f.write("2. IP matching: IP in attack_ips list → attack\n")
            f.write("3. Default: all other traffic → benign\n")
            
        print(f"[*] Summary report generated: {summary_file}")
        
    def process(self, attack_log: str, nginx_log: str, output_dir: str):
        """Main processing method"""
        print("[*] Starting ground truth label generation...")
        
        # Extract attack information
        if not self.extract_attack_info(attack_log):
            return False
            
        # Parse nginx log
        if not self.parse_nginx_log(nginx_log):
            return False
            
        # Generate labels
        self.labeled_records = self.generate_labels()
        
        # Export results
        csv_file = os.path.join(output_dir, 'gt_labeled_nginx_records.csv')
        json_file = os.path.join(output_dir, 'gt_labeled_nginx_records.json')
        
        self.export_to_csv(csv_file, self.labeled_records)
        self.export_to_json(json_file, self.labeled_records)
        
        # Generate summary
        self.generate_summary(output_dir)
        
        print("[*] Ground truth label generation completed!")
        return True

def main():
    parser = argparse.ArgumentParser(description='Ground Truth Label Generator')
    parser.add_argument('--attack-log', required=True, help='Path to attack script log')
    parser.add_argument('--nginx-log', required=True, help='Path to nginx detailed log')
    parser.add_argument('--output-dir', required=True, help='Output directory for labeled data')
    
    args = parser.parse_args()
    
    generator = GTLabelGenerator()
    success = generator.process(
        attack_log=args.attack_log,
        nginx_log=args.nginx_log,
        output_dir=args.output_dir
    )
    
    if not success:
        sys.exit(1)

if __name__ == '__main__':
    main() 