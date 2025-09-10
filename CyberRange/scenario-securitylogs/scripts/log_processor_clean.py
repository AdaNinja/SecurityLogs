#!/usr/bin/env python3
"""
Clean Log Processor for RAS Security Logs
Parses nginx detailed.log and outputs structured data WITHOUT classification
All traffic is marked as 'unknown' for manual review
"""

import re
import json
import csv
import sys
import os
from datetime import datetime
from collections import defaultdict
import argparse

class CleanLogProcessor:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.processed_logs = []
        
        # NO ATTACK INDICATORS - Clean slate for manual review
        self.attack_user_agents = []
        self.attacker_ips = []
        self.attack_paths = []
        self.attack_methods = []
        
    def parse_nginx_log_line(self, line):
        """Parse a single nginx log line"""
        # nginx detailed log format:
        # $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for" $request_time $upstream_response_time "$request_body"
        
        pattern = r'^(\S+) - (\S+) \[([^\]]+)\] "([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)" "([^"]*)" (\S+) (\S+) "([^"]*)"$'
        match = re.match(pattern, line.strip())
        
        if not match:
            return None
            
        try:
            remote_addr, remote_user, time_local, request, status, body_bytes_sent, referer, user_agent, x_forwarded_for, request_time, upstream_response_time, request_body = match.groups()
            
            # Parse request
            request_parts = request.split(' ')
            if len(request_parts) >= 2:
                method = request_parts[0]
                url = request_parts[1]
            else:
                method = 'UNKNOWN'
                url = request
                
            # Parse URL
            url_parts = url.split('?')
            path = url_parts[0]
            query_string = url_parts[1] if len(url_parts) > 1 else ''
            
            # Parse timestamp
            try:
                timestamp = datetime.strptime(time_local, '%d/%b/%Y:%H:%M:%S %z')
            except:
                timestamp = time_local
                
            return {
                'timestamp': timestamp,
                'remote_addr': remote_addr,
                'remote_user': remote_user,
                'method': method,
                'path': path,
                'query_string': query_string,
                'full_url': url,
                'status_code': int(status),
                'body_bytes_sent': int(body_bytes_sent),
                'referer': referer,
                'user_agent': user_agent,
                'x_forwarded_for': x_forwarded_for,
                'request_time': float(request_time) if request_time != '-' else 0.0,
                'upstream_response_time': float(upstream_response_time) if upstream_response_time != '-' else 0.0,
                'request_body': request_body,
                'raw_line': line.strip()
            }
        except Exception as e:
            print(f"Error parsing line: {e}")
            return None
            
    def classify_traffic(self, log_entry):
        """Classify traffic as unknown (no automatic classification)"""
        # ALL TRAFFIC IS MARKED AS UNKNOWN FOR MANUAL REVIEW
        return 'unknown'
        
    def process_log_file(self, limit=None, sample=None):
        """Process the entire log file with optional limits"""
        if not os.path.exists(self.log_file_path):
            print(f"Error: Log file not found: {self.log_file_path}")
            return False
            
        print(f"[*] Processing log file: {self.log_file_path}")
        print(f"[*] NOTE: All traffic will be marked as 'unknown' for manual review")
        
        # Read all lines first
        with open(self.log_file_path, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]
        
        # Apply sampling if requested
        if sample and sample < len(lines):
            import random
            lines = random.sample(lines, sample)
            print(f"[*] Sampled {sample} lines from {len(lines)} total lines")
        
        # Apply limit if requested
        if limit:
            lines = lines[:limit]
            print(f"[*] Limited to {limit} lines")
        
        # Process lines
        for line_num, line in enumerate(lines, 1):
            log_entry = self.parse_nginx_log_line(line)
            if log_entry:
                log_entry['classification'] = self.classify_traffic(log_entry)
                log_entry['line_number'] = line_num
                self.processed_logs.append(log_entry)
                        
        print(f"[*] Processed {len(self.processed_logs)} log entries")
        return True
        
    def get_statistics(self):
        """Get processing statistics"""
        if not self.processed_logs:
            return {}
            
        stats = {
            'total_entries': len(self.processed_logs),
            'attack_entries': len([e for e in self.processed_logs if e['classification'] == 'attack']),
            'benign_entries': len([e for e in self.processed_logs if e['classification'] == 'benign']),
            'unknown_entries': len([e for e in self.processed_logs if e['classification'] == 'unknown']),
            'unique_ips': len(set(e['remote_addr'] for e in self.processed_logs)),
            'unique_user_agents': len(set(e['user_agent'] for e in self.processed_logs if e['user_agent'])),
            'status_codes': defaultdict(int),
            'methods': defaultdict(int),
            'top_paths': defaultdict(int),
            'top_user_agents': defaultdict(int)
        }
        
        for entry in self.processed_logs:
            stats['status_codes'][entry['status_code']] += 1
            stats['methods'][entry['method']] += 1
            stats['top_paths'][entry['path']] += 1
            if entry['user_agent']:
                stats['top_user_agents'][entry['user_agent']] += 1
                
        return stats
        
    def export_to_csv(self, output_file):
        """Export processed logs to CSV"""
        if not self.processed_logs:
            print("No processed logs to export")
            return False
            
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'timestamp', 'remote_addr', 'method', 'path', 'query_string',
                    'status_code', 'user_agent', 'referer', 'request_time',
                    'upstream_response_time', 'request_body', 'classification'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for entry in self.processed_logs:
                    # Convert timestamp to string if it's a datetime object
                    timestamp = entry['timestamp']
                    if hasattr(timestamp, 'strftime'):
                        timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                    
                    writer.writerow({
                        'timestamp': timestamp,
                        'remote_addr': entry['remote_addr'],
                        'method': entry['method'],
                        'path': entry['path'],
                        'query_string': entry['query_string'],
                        'status_code': entry['status_code'],
                        'user_agent': entry['user_agent'],
                        'referer': entry['referer'],
                        'request_time': entry['request_time'],
                        'upstream_response_time': entry['upstream_response_time'],
                        'request_body': entry['request_body'],
                        'classification': entry['classification']
                    })
                    
            print(f"[*] Exported {len(self.processed_logs)} entries to {output_file}")
            return True
            
        except Exception as e:
            print(f"Error exporting to CSV: {e}")
            return False
            
    def export_to_json(self, output_file):
        """Export processed logs to JSON"""
        if not self.processed_logs:
            print("No processed logs to export")
            return False
            
        try:
            # Convert datetime objects to strings for JSON serialization
            json_data = []
            for entry in self.processed_logs:
                entry_copy = entry.copy()
                if hasattr(entry_copy['timestamp'], 'strftime'):
                    entry_copy['timestamp'] = entry_copy['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                json_data.append(entry_copy)
                
            with open(output_file, 'w', encoding='utf-8') as jsonfile:
                json.dump(json_data, jsonfile, indent=2, ensure_ascii=False)
                
            print(f"[*] Exported {len(self.processed_logs)} entries to {output_file}")
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
        print("LOG PROCESSING SUMMARY (CLEAN VERSION)")
        print("=" * 60)
        print(f"Total entries processed: {stats['total_entries']}")
        print(f"Attack entries: {stats['attack_entries']}")
        print(f"Benign entries: {stats['benign_entries']}")
        print(f"Unknown entries: {stats['unknown_entries']}")
        print(f"Unique IP addresses: {stats['unique_ips']}")
        print(f"Unique User-Agents: {stats['unique_user_agents']}")
        print()
        
        print("Top 5 Status Codes:")
        for code, count in sorted(stats['status_codes'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {code}: {count}")
        print()
        
        print("Top 5 HTTP Methods:")
        for method, count in sorted(stats['methods'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {method}: {count}")
        print()
        
        print("Top 5 Requested Paths:")
        for path, count in sorted(stats['top_paths'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {path}: {count}")
        print()
        
        print("Top 5 User-Agents:")
        for ua, count in sorted(stats['top_user_agents'].items(), key=lambda x: x[1], reverse=True)[:5]:
            # Truncate long user agents
            ua_short = ua[:50] + "..." if len(ua) > 50 else ua
            print(f"  {ua_short}: {count}")
        print("=" * 60)

def main():
    parser = argparse.ArgumentParser(description='Clean Log Processor for RAS Security Logs')
    parser.add_argument('log_file', help='Path to nginx detailed.log file')
    parser.add_argument('--output-csv', help='Output CSV file path')
    parser.add_argument('--output-json', help='Output JSON file path')
    parser.add_argument('--summary-only', action='store_true', help='Only print summary, no export')
    parser.add_argument('--limit', type=int, help='Limit number of lines to process')
    parser.add_argument('--sample', type=int, help='Sample random lines to process')
    
    args = parser.parse_args()
    
    # Initialize processor
    processor = CleanLogProcessor(args.log_file)
    
    # Process log file
    if not processor.process_log_file(limit=args.limit, sample=args.sample):
        sys.exit(1)
    
    # Print summary
    processor.print_summary()
    
    # Export if requested
    if not args.summary_only:
        if args.output_csv:
            processor.export_to_csv(args.output_csv)
        if args.output_json:
            processor.export_to_json(args.output_json)
        
        # Default export if no specific output specified
        if not args.output_csv and not args.output_json:
            processor.export_to_csv('clean_processed_logs.csv')
            processor.export_to_json('clean_processed_logs.json')

if __name__ == '__main__':
    main() 