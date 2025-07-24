#!/usr/bin/env python3
"""
DNS Log Parser for SecurityLogs
Converts dnsmasq logs to unified JSONL format
"""

import re
import json
import sys
import os
from datetime import datetime
from typing import Dict, Any, Optional

class DNSLogParser:
    def __init__(self, log_file: str, variant_id: Optional[str] = None):
        self.log_file = log_file
        self.variant_id = variant_id
        self.output_file = self._get_output_filename(log_file)
        
        # DNS log patterns
        self.patterns = {
            'query': re.compile(r'(\d+)\s+(\d+/\d+/\d+\s+\d+:\d+:\d+)\s+query\[([A-Z]+)\]\s+([^\s]+)\s+from\s+([^\s]+)'),
            'reply': re.compile(r'(\d+)\s+(\d+/\d+/\d+\s+\d+:\d+:\d+)\s+reply\s+([^\s]+)\s+([A-Z]+)\s+([^\s]+)\s+is\s+([^\s]+)'),
            'cached': re.compile(r'(\d+)\s+(\d+/\d+/\d+\s+\d+:\d+:\d+)\s+cached\s+([^\s]+)\s+([A-Z]+)\s+([^\s]+)'),
            'forwarded': re.compile(r'(\d+)\s+(\d+/\d+/\d+\s+\d+:\d+:\d+)\s+forwarded\s+([^\s]+)\s+([A-Z]+)\s+to\s+([^\s]+)'),
            'failed': re.compile(r'(\d+)\s+(\d+/\d+/\d+\s+\d+:\d+:\d+)\s+failed\s+([^\s]+)\s+([A-Z]+)\s+from\s+([^\s]+)')
        }
    
    def _get_output_filename(self, log_file: str) -> str:
        """Generate output filename based on input log file"""
        base_name = os.path.splitext(os.path.basename(log_file))[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if self.variant_id:
            # Create variant-specific directory in processed
            output_dir = f"data/processed/{self.variant_id}/dns_data"
            os.makedirs(output_dir, exist_ok=True)
            return f"{output_dir}/{base_name}_{timestamp}.jsonl"
        else:
            # Fallback to original location
            return f"data/processed/dns_data/{base_name}_{timestamp}.jsonl"
    
    def _parse_timestamp(self, timestamp_str: str) -> str:
        """Parse dnsmasq timestamp to ISO format"""
        try:
            # dnsmasq format: DD/MM/YYYY HH:MM:SS
            dt = datetime.strptime(timestamp_str, "%d/%m/%Y %H:%M:%S")
            return dt.isoformat() + "Z"
        except ValueError:
            return timestamp_str
    
    def _is_attack_query(self, domain: str) -> bool:
        """Determine if DNS query is part of an attack"""
        suspicious_domains = [
            'malware', 'virus', 'exploit', 'hack', 'attack', 'backdoor',
            'trojan', 'worm', 'spyware', 'keylogger', 'rootkit',
            'attacker', 'tunnel', 'exfil', 'cc', 'command', 'control'
        ]
        
        # Check for DNS tunneling patterns
        tunneling_patterns = [
            r'[A-Za-z0-9+/]{20,}',  # Long base64-like strings
            r'cmd\.',               # Command patterns
            r'tunnel\.',            # Tunnel patterns
            r'exfil\.',             # Exfiltration patterns
        ]
        
        domain_lower = domain.lower()
        
        # Check suspicious keywords
        if any(susp in domain_lower for susp in suspicious_domains):
            return True
        
        # Check tunneling patterns
        for pattern in tunneling_patterns:
            if re.search(pattern, domain):
                return True
        
        return False
    
    def _determine_attack_stage(self, domain: str, record_type: str = None) -> str:
        """Determine attack stage based on domain and record type"""
        if self._is_attack_query(domain):
            # Determine specific attack stage based on patterns
            if 'cmd.' in domain or 'command.' in domain:
                return "command_control"
            elif 'tunnel.' in domain or 'exfil.' in domain:
                return "data_exfiltration"
            elif any(pattern in domain for pattern in ['admin', 'api', 'db', 'internal']):
                return "reconnaissance"
            else:
                return "reconnaissance"
        
        # For normal DNS queries, determine stage based on record type
        if record_type in ['A', 'AAAA']:
            return "reconnaissance"
        elif record_type in ['MX', 'NS']:
            return "reconnaissance"
        else:
            return "normal"
    
    def _parse_query_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse DNS query log entry"""
        match = self.patterns['query'].match(line)
        if match:
            record = {
                "timestamp": self._parse_timestamp(match.group(2)),
                "host": "dns_proxy",
                "source_type": "dns_query",
                "event_type": "dns_query",
                "severity": "info",
                "process": "dnsmasq",
                "user": None,
                "is_attack": self._is_attack_query(match.group(4)),
                "attack_stage": self._determine_attack_stage(match.group(4)),
                "details": {
                    "raw": line.strip(),
                    "query_id": match.group(1),
                    "record_type": match.group(3),
                    "domain": match.group(4),
                    "client_ip": match.group(5),
                    "action": "query"
                }
            }
            if self.variant_id:
                record["variant_id"] = self.variant_id
            return record
        return None
    
    def _parse_reply_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse DNS reply log entry"""
        match = self.patterns['reply'].match(line)
        if match:
            record = {
                "timestamp": self._parse_timestamp(match.group(2)),
                "host": "dns_proxy",
                "source_type": "dns_reply",
                "event_type": "dns_reply",
                "severity": "info",
                "process": "dnsmasq",
                "user": None,
                "is_attack": self._is_attack_query(match.group(3)),
                "attack_stage": self._determine_attack_stage(match.group(3), match.group(4)),
                "details": {
                    "raw": line.strip(),
                    "query_id": match.group(1),
                    "domain": match.group(3),
                    "record_type": match.group(4),
                    "response": match.group(5),
                    "source": match.group(6),
                    "action": "reply"
                }
            }
            if self.variant_id:
                record["variant_id"] = self.variant_id
            return record
        return None
    
    def _parse_cached_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse DNS cached log entry"""
        match = self.patterns['cached'].match(line)
        if match:
            record = {
                "timestamp": self._parse_timestamp(match.group(2)),
                "host": "dns_proxy",
                "source_type": "dns_cached",
                "event_type": "dns_cached",
                "severity": "info",
                "process": "dnsmasq",
                "user": None,
                "is_attack": self._is_attack_query(match.group(3)),
                "attack_stage": self._determine_attack_stage(match.group(3), match.group(4)),
                "details": {
                    "raw": line.strip(),
                    "query_id": match.group(1),
                    "domain": match.group(3),
                    "record_type": match.group(4),
                    "response": match.group(5),
                    "action": "cached"
                }
            }
            if self.variant_id:
                record["variant_id"] = self.variant_id
            return record
        return None
    
    def _parse_forwarded_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse DNS forwarded log entry"""
        match = self.patterns['forwarded'].match(line)
        if match:
            record = {
                "timestamp": self._parse_timestamp(match.group(2)),
                "host": "dns_proxy",
                "source_type": "dns_forwarded",
                "event_type": "dns_forwarded",
                "severity": "info",
                "process": "dnsmasq",
                "user": None,
                "is_attack": None,
                "attack_stage": "reconnaissance",
                "details": {
                    "raw": line.strip(),
                    "query_id": match.group(1),
                    "domain": match.group(3),
                    "record_type": match.group(4),
                    "upstream_server": match.group(5),
                    "action": "forwarded"
                }
            }
            if self.variant_id:
                record["variant_id"] = self.variant_id
            return record
        return None
    
    def _parse_failed_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse DNS failed log entry"""
        match = self.patterns['failed'].match(line)
        if match:
            record = {
                "timestamp": self._parse_timestamp(match.group(2)),
                "host": "dns_proxy",
                "source_type": "dns_failed",
                "event_type": "dns_failed",
                "severity": "warning",
                "process": "dnsmasq",
                "user": None,
                "is_attack": None,
                "attack_stage": "reconnaissance",
                "details": {
                    "raw": line.strip(),
                    "query_id": match.group(1),
                    "domain": match.group(3),
                    "record_type": match.group(4),
                    "client_ip": match.group(5),
                    "action": "failed"
                }
            }
            if self.variant_id:
                record["variant_id"] = self.variant_id
            return record
        return None
    
    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a single DNS log line"""
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            return None
        
        # Try different patterns
        for parser_func in [
            self._parse_query_log,
            self._parse_reply_log,
            self._parse_cached_log,
            self._parse_forwarded_log,
            self._parse_failed_log
        ]:
            result = parser_func(line)
            if result:
                return result
        
        # If no pattern matches, create a generic entry
        record = {
            "timestamp": datetime.now().isoformat() + "Z",
            "host": "dns_proxy",
            "source_type": "dns_unknown",
            "event_type": "dns_unknown",
            "severity": "info",
            "process": "dnsmasq",
            "user": None,
            "is_attack": None,
            "attack_stage": "normal",  # Changed from "reconnaissance" to "normal"
            "details": {
                "raw": line,
                "action": "unknown"
            }
        }
        if self.variant_id:
            record["variant_id"] = self.variant_id
        return record
    
    def parse_log_file(self):
        """Parse the entire DNS log file"""
        print(f"Parsing DNS log file: {self.log_file}")
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
        
        parsed_entries = 0
        skipped_entries = 0
        
        with open(self.log_file, 'r', encoding='utf-8') as infile:
            with open(self.output_file, 'w', encoding='utf-8') as outfile:
                for line_num, line in enumerate(infile, 1):
                    try:
                        parsed_entry = self.parse_line(line)
                        if parsed_entry:
                            outfile.write(json.dumps(parsed_entry) + '\n')
                            parsed_entries += 1
                        else:
                            skipped_entries += 1
                    except Exception as e:
                        print(f"Error parsing line {line_num}: {e}")
                        skipped_entries += 1
        
        print(f"Parsing completed:")
        print(f"  Parsed entries: {parsed_entries}")
        print(f"  Skipped entries: {skipped_entries}")
        print(f"  Output file: {self.output_file}")
        
        return parsed_entries

def parse_dns_logs(variant_id=None):
    """Parse DNS logs and convert to JSON Lines format"""
    print(f"🚀 Processing DNS logs for variant: {variant_id}")
    
    # Create variant-specific output directory
    output_dir = f"data/processed/{variant_id}/dns_data"
    os.makedirs(output_dir, exist_ok=True)
    
    # Look for DNS log files in the variant's logs directory
    possible_paths = [
        f"data/logs/{variant_id}/system/user.log",  # System logs now in system/
        f"data/logs/{variant_id}/system/dns.log",
        f"data/logs/{variant_id}/system/dnsmasq.log",
        f"data/logs/{variant_id}/system/dns_server.log",
        f"data/logs/{variant_id}/system/*dns*.log",
        f"data/logs/{variant_id}/system/*.log"
    ]
    
    dns_log_file = None
    for path in possible_paths:
        if '*' in path:
            # Handle glob patterns
            import glob
            files = glob.glob(path)
            if files:
                dns_log_file = files[0]
                print(f"Found DNS log file: {dns_log_file}")
                break
        elif os.path.exists(path):
            dns_log_file = path
            print(f"Found DNS log file: {dns_log_file}")
            break
    
    if not dns_log_file:
        print(f"❌ DNS log file not found for variant: {variant_id}")
        return False
    
    if not os.path.exists(dns_log_file):
        print(f"❌ DNS log file not found: {dns_log_file}")
        return False
    
    print(f"Parsing DNS log file: {dns_log_file}")
    if variant_id:
        print(f"Using variant_id: {variant_id}")
    
    # Generate output filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"dnsmasq_{timestamp}.jsonl")
    
    # Use DNSLogParser class
    parser = DNSLogParser(dns_log_file, variant_id)
    parser.output_file = output_file  # Override output file path
    
    try:
        parsed_count = parser.parse_log_file()
        return True
        
    except Exception as e:
        print(f"❌ Error parsing DNS logs: {e}")
        return False

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Parse DNS logs and convert to JSON Lines format")
    parser.add_argument("--variant-id", help="Variant ID for the experiment")
    parser.add_argument("--dns-log-file", help="DNS log file to parse")
    
    args = parser.parse_args()
    
    # If no dns_log_file specified, try to find one for the variant
    dns_log_file = args.dns_log_file
    if not dns_log_file and args.variant_id:
        # Look for DNS log files in the variant's logs directory
        possible_paths = [
            f"data/logs/{args.variant_id}/system/user.log",
            f"data/logs/{args.variant_id}/system/dns.log",
            f"data/logs/{args.variant_id}/system/dnsmasq.log",
            f"data/logs/{args.variant_id}/system/dns_server.log",
            f"data/logs/{args.variant_id}/system/*dns*.log",
            f"data/logs/{args.variant_id}/system/*.log"
        ]
        
        for path in possible_paths:
            if '*' in path:
                # Handle glob patterns
                import glob
                files = glob.glob(path)
                if files:
                    dns_log_file = files[0]
                    print(f"Found DNS log file: {dns_log_file}")
                    break
            elif os.path.exists(path):
                dns_log_file = path
                print(f"Found DNS log file: {dns_log_file}")
                break
    
    if not dns_log_file:
        print("Warning: No DNS log file found, skipping DNS log parsing")
        return
    
    if not os.path.exists(dns_log_file):
        print(f"Error: DNS log file not found: {dns_log_file}")
        return
    
    print(f"Parsing DNS log file: {dns_log_file}")
    if args.variant_id:
        print(f"Using variant_id: {args.variant_id}")
    
    parser = DNSLogParser(dns_log_file, args.variant_id)
    parser.parse_log_file()

if __name__ == "__main__":
    main() 