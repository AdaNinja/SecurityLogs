#!/usr/bin/env python3
"""
Log Processor for RAS Security Logs
Parses nginx detailed.log and outputs structured data with attack/benign classification
"""

import re
import json
import csv
import sys
import os
from datetime import datetime
from collections import defaultdict
import argparse

class LogProcessor:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.processed_logs = []
        
        # Attack indicators
        self.attack_user_agents = [
            'attacker',
            'sqlmap',
            'nmap',
            'dirb',
            'slowhttptest',
            'Enhanced-Container-Attacker'
        ]
        
        # Note: In real-world scenarios, we cannot know attacker IPs in advance
        # IP-based detection should be based on behavior patterns, not hardcoded IPs
        # This is only for demonstration purposes in controlled environments
        self.attacker_ips = []  # Empty list - no hardcoded IPs
        
        self.attack_paths = [
            '/login.php',
            '/admin',
            '/wp-admin',
            '/phpmyadmin',
            '/.env',
            '/.git',
            '/config',
            '/backup',
            '/shell',
            '/cmd',
            '/exec',
            '/system',
            '/union',
            '/select',
            '/insert',
            '/update',
            '/delete',
            '/drop',
            '/create',
            '/alter'
        ]
        
        self.attack_methods = [
            'POST /rest/user/login',
            'POST /api/Users/'
            # Removed 'GET /rest/products/search' as it's a legitimate benign endpoint
        ]
        
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
        """Classify traffic as attack or benign"""
        if not log_entry:
            return 'unknown'
            
        # Check User-Agent with fuzzy matching
        user_agent = log_entry.get('user_agent', '').lower()
        for attack_ua in self.attack_user_agents:
            if attack_ua.lower() in user_agent:
                return 'attack'
        
        # Check for attack tool patterns in User-Agent
        attack_patterns = [
            r'sqlmap[\/\-\d\.]*',
            r'nmap[\/\-\d\.]*',
            r'dirb[\/\-\d\.]*',
            r'slowhttptest[\/\-\d\.]*',
            r'nikto[\/\-\d\.]*',
            r'hydra[\/\-\d\.]*',
            r'wpscan[\/\-\d\.]*',
            r'gobuster[\/\-\d\.]*'
        ]
        
        for pattern in attack_patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):
                return 'attack'
                
        # Check path with enhanced detection
        path = log_entry.get('path', '').lower()
        for attack_path in self.attack_paths:
            if attack_path.lower() in path:
                return 'attack'
        
        # Check for attack patterns in path using regex
        path_attack_patterns = [
            r'\b(admin|wp-admin|phpmyadmin|config|backup|shell|cmd|exec|system)\b',
            r'\.(env|git|bak|old|tmp|log|ini|conf)$',
            r'\b(union|select|insert|update|delete|drop|create|alter)\b',
            r'\/\.(htaccess|htpasswd)',
            r'\/wp-content\/uploads\/.*\.(php|jsp|asp)',
            r'\/includes\/.*\.(php|jsp|asp)'
        ]
        
        for pattern in path_attack_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return 'attack'
                
        # Check query string for SQL injection patterns with enhanced regex
        query_string = log_entry.get('query_string', '')
        sql_injection_patterns = [
            r'\b(union|select|insert|update|delete|drop|create|alter|exec|system)\b',
            r'(\'|\")\s*(or|and)\s*(\'|\"|\d+)\s*[=<>]\s*(\'|\"|\d+)',
            r'(\'|\")\s*--\s*$',
            r'(\'|\")\s*#\s*$',
            r'(\'|\")\s*/\*.*\*/\s*$',
            r'(\'|\")\s*union\s+select\b',
            r'(\'|\")\s*or\s+1\s*=\s*1\b',
            r'(\'|\")\s*and\s+1\s*=\s*1\b',
            r'(\'|\")\s*or\s+\'1\'\s*=\s*\'1\b',
            r'(\'|\")\s*and\s+\'1\'\s*=\s*\'1\b'
        ]
        
        for pattern in sql_injection_patterns:
            if re.search(pattern, query_string, re.IGNORECASE):
                return 'attack'
                
        # Check request body for SQL injection patterns
        request_body = log_entry.get('request_body', '')
        for pattern in sql_injection_patterns:
            if re.search(pattern, request_body, re.IGNORECASE):
                return 'attack'
                
        # Check method + path combination
        method_path = f"{log_entry.get('method', '')} {log_entry.get('path', '')}"
        if method_path in self.attack_methods:
            return 'attack'
        
        # Check source IP address (only for known attack patterns)
        # In real-world, we would use behavioral analysis instead of hardcoded IPs
        remote_addr = log_entry.get('remote_addr', '')
        
        # Only use IP detection if we have behavioral evidence
        # This is more realistic than hardcoded IP lists
        if remote_addr in self.attacker_ips:
            return 'attack'
        
        # Realistic IP-based detection would be:
        # 1. Rate limiting (too many requests from same IP)
        # 2. Geographic anomalies (unusual locations)
        # 3. Behavioral patterns (specific attack sequences)
        # 4. Reputation lists (known malicious IPs from threat intel)
        # 
        # For now, we focus on payload and User-Agent based detection
        # which is more reliable and doesn't require prior knowledge
        
        # Check for suspicious request patterns
        suspicious_patterns = [
            r'\.\./',  # Directory traversal
            r'%2e%2e%2f',  # URL encoded directory traversal
            r'%252e%252e%252f',  # Double URL encoded
            r'<script',  # XSS attempts
            r'javascript:',  # XSS attempts
            r'data:text/html',  # XSS attempts
            r'vbscript:',  # XSS attempts
            r'onload=',  # XSS attempts
            r'onerror=',  # XSS attempts
            r'<iframe',  # XSS attempts
        ]
        
        full_url = log_entry.get('path', '') + log_entry.get('query_string', '')
        for pattern in suspicious_patterns:
            if re.search(pattern, full_url, re.IGNORECASE):
                return 'attack'
            
        return 'benign'
        
    def process_log_file(self, limit=None, sample=None):
        """Process the entire log file with optional limits"""
        if not os.path.exists(self.log_file_path):
            print(f"Error: Log file not found: {self.log_file_path}")
            return False
            
        print(f"[*] Processing log file: {self.log_file_path}")
        
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
            print("[!] No processed logs to export")
            return False
            
        print(f"[*] Exporting to CSV: {output_file}")
        
        fieldnames = [
            'timestamp', 'remote_addr', 'method', 'path', 'query_string', 
            'status_code', 'user_agent', 'referer', 'request_time', 
            'upstream_response_time', 'request_body', 'classification'
        ]
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for entry in self.processed_logs:
                row = {field: entry.get(field, '') for field in fieldnames}
                # Convert timestamp to string if it's a datetime object
                if isinstance(row['timestamp'], datetime):
                    row['timestamp'] = row['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                writer.writerow(row)
                
        print(f"[*] Exported {len(self.processed_logs)} entries to {output_file}")
        return True
        
    def export_to_json(self, output_file):
        """Export processed logs to JSON"""
        if not self.processed_logs:
            print("[!] No processed logs to export")
            return False
            
        print(f"[*] Exporting to JSON: {output_file}")
        
        # Convert datetime objects to strings for JSON serialization
        json_data = []
        for entry in self.processed_logs:
            json_entry = entry.copy()
            if isinstance(json_entry['timestamp'], datetime):
                json_entry['timestamp'] = json_entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            json_data.append(json_entry)
            
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
            
        print(f"[*] Exported {len(self.processed_logs)} entries to {output_file}")
        return True
        
    def print_summary(self):
        """Print processing summary"""
        stats = self.get_statistics()
        
        print("\n" + "=" * 60)
        print("LOG PROCESSING SUMMARY")
        print("=" * 60)
        print(f"Total entries processed: {stats['total_entries']}")
        print(f"Attack entries: {stats['attack_entries']} ({stats['attack_entries']/stats['total_entries']*100:.1f}%)")
        print(f"Benign entries: {stats['benign_entries']} ({stats['benign_entries']/stats['total_entries']*100:.1f}%)")
        print(f"Unknown entries: {stats['unknown_entries']} ({stats['unknown_entries']/stats['total_entries']*100:.1f}%)")
        print(f"Unique IP addresses: {stats['unique_ips']}")
        print(f"Unique User-Agents: {stats['unique_user_agents']}")
        
        print("\nTop 5 Status Codes:")
        for status, count in sorted(stats['status_codes'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {status}: {count}")
            
        print("\nTop 5 HTTP Methods:")
        for method, count in sorted(stats['methods'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {method}: {count}")
            
        print("\nTop 5 Requested Paths:")
        for path, count in sorted(stats['top_paths'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {path}: {count}")
            
        print("\nTop 5 User-Agents:")
        for ua, count in sorted(stats['top_user_agents'].items(), key=lambda x: x[1], reverse=True)[:5]:
            ua_short = ua[:50] + "..." if len(ua) > 50 else ua
            print(f"  {ua_short}: {count}")
            
        print("=" * 60)

def main():
    parser = argparse.ArgumentParser(description='Process nginx logs and classify traffic')
    parser.add_argument('log_file', help='Path to nginx log file')
    parser.add_argument('--output-csv', help='Output CSV file path')
    parser.add_argument('--output-json', help='Output JSON file path')
    parser.add_argument('--summary-only', action='store_true', help='Only print summary, no export')
    parser.add_argument('--limit', type=int, help='Limit number of log entries to process (default: all)')
    parser.add_argument('--sample', type=int, help='Sample N log entries for quick testing')
    
    args = parser.parse_args()
    
    # Initialize processor
    processor = LogProcessor(args.log_file)
    
    # Process log file with optional limits
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
            
        # Default exports if no specific output specified
        if not args.output_csv and not args.output_json:
            processor.export_to_csv('processed_logs.csv')
            processor.export_to_json('processed_logs.json')

if __name__ == "__main__":
    main() 