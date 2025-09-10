#!/usr/bin/env python3
"""
Mapping GT Label to Network Traffic
output: network_traffic.csv
"""

import os
import sys
import json
import logging
import pandas as pd
import re
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class NetworkTrafficGenerator:
    """Network Traffic CSV Generator"""
    
    def __init__(self):
        self.nginx_records = []
        self.pcap_records = []
        
    def load_nginx_csv(self, nginx_csv_path: str) -> bool:
        """Load nginx_detailed.csv"""
        try:
            # Read CSV, handle possible format issues
            df = pd.read_csv(nginx_csv_path, 
                           on_bad_lines='skip', 
                           quoting=1)  
            
            self.nginx_records = df.to_dict('records')
            logger.info(f"Loaded {len(self.nginx_records)} records from nginx CSV")
            return True
        except Exception as e:
            logger.error(f"Failed to load nginx CSV: {e}")
            return False
    
    def load_nginx_log(self, nginx_log_path: str) -> bool:
        """Load nginx detailed.log to get complete attack information"""
        try:
            records = []
            # Parse detailed log format (new format)
            # Format: IP:Port - - [timestamp] "request" status size "referer" "user_agent" "attack-id" "traffic-type" "attack-type" "event-id" "chain-id" "phase" "category" "msec" "connection"
            pattern = r'^(\S+) - - \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)"'
            
            with open(nginx_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    match = re.match(pattern, line.strip())
                    if match:
                        groups = match.groups()
                        # Parse request
                        request_parts = groups[2].split()
                        method = request_parts[0] if request_parts else "UNKNOWN"
                        path = request_parts[1] if len(request_parts) > 1 else "/"
                        
                        record = {
                            'ip_src': groups[0],
                            'timestamp': groups[1],
                            'request': groups[2],
                            'status_code': groups[3],
                            'size': groups[4],
                            'referer': groups[5],
                            'user_agent': groups[6],
                            'attack_id': groups[7],  # payload_id in new format
                            'traffic_type': groups[8],
                            'attack_type': groups[9],
                            'event_id': groups[10],
                            'chain_id': groups[11],
                            'phase': groups[12],
                            'category': groups[13],
                            'msec': groups[14],
                            'connection': groups[15],
                            'method': method,
                            'path': path
                        }
                        records.append(record)
            
            self.nginx_log_records = records
            logger.info(f"Loaded {len(records)} records from nginx detailed log")
            return True
        except Exception as e:
            logger.error(f"Failed to load nginx log: {e}")
            return False
    
    def load_pcap_csv(self, pcap_csv_path: str) -> bool:
        """Load network_traffic_traffic.csv (from PCAP parsed traffic data)"""
        try:
            df = pd.read_csv(pcap_csv_path)
            self.pcap_records = df.to_dict('records')
            logger.info(f"Loaded {len(self.pcap_records)} records from PCAP CSV")
            return True
        except Exception as e:
            logger.error(f"Failed to load PCAP CSV: {e}")
            return False
    
    def generate_network_traffic_csv(self, output_path: str) -> bool:
        """Generate labeled network_traffic.csv"""
        try:
            labeled_flows = []
            
            # Use nginx log records first (if loaded)
            records_to_use = self.nginx_log_records if hasattr(self, 'nginx_log_records') else self.nginx_records
            
            # Create flow record for each nginx record
            for nginx_record in records_to_use:
                # Extract key information
                timestamp = nginx_record.get('timestamp', '')
                ip_src = nginx_record.get('ip_src', '')
                request_method = nginx_record.get('method', nginx_record.get('request_method', ''))
                request_path = nginx_record.get('path', nginx_record.get('request_path', ''))
                response_code = nginx_record.get('status_code', nginx_record.get('response_code', 200))
                
                # Determine if it's an attack from nginx log
                if 'traffic_type' in nginx_record:
                    # Use traffic_type field
                    is_attack = nginx_record.get('traffic_type') == 'attack'
                    payload = nginx_record.get('attack_id', '') if nginx_record.get('attack_id', '') not in ['-', ''] else ''
                    attack_type = nginx_record.get('attack_type', '')
                    chain_id = nginx_record.get('chain_id', '')
                    phase = nginx_record.get('phase', '')
                    event_id = nginx_record.get('event_id', '')
                else:
                    # From CSV record
                    label = nginx_record.get('label', 0)
                    is_attack = label == 1 or label == '1'
                    payload = nginx_record.get('payload', '')
                    attack_type = ''
                    chain_id = ''
                    phase = ''
                    event_id = ''
                
                # Generate event stage label
                if 'traffic_type' in nginx_record:
                    # Use information from nginx log
                    event_stage_label = self._generate_event_stage_label_from_log(
                        is_attack, payload, chain_id, phase, attack_type, event_id
                    )
                else:
                    event_stage_label = self._generate_event_stage_label(
                        is_attack, payload, nginx_record
                    )
                
                # Create flow record
                flow_record = {
                    'timestamp': timestamp,
                    'src_ip': ip_src,
                    'dst_ip': '172.18.0.2',  # nginx container IP 
                    'src_port': 0,  # Cannot get from old format log
                    'dst_port': 80,
                    'protocol': 'TCP',
                    'packets': 1,
                    'bytes': int(nginx_record.get('size', 0)) if 'size' in nginx_record else 1000,
                    'duration': 0.1,  # Default duration
                    'http_method': request_method,
                    'http_path': request_path,
                    'http_status': response_code,
                    'binary_label': 1 if is_attack else 0,
                    'event_stage_label': event_stage_label,
                    'attack_type': self._extract_attack_type(attack_type if 'traffic_type' in nginx_record else payload) if is_attack else '',
                    'confidence': 'high'  # High confidence based on nginx log
                }
                
                labeled_flows.append(flow_record)
            
            # Create DataFrame and save
            df = pd.DataFrame(labeled_flows)
            
            # Add statistics column
            df['flow_id'] = range(1, len(df) + 1)
            
            # Save CSV
            df.to_csv(output_path, index=False)
            
            # Generate statistics
            stats = {
                'total_flows': len(df),
                'attack_flows': len(df[df['binary_label'] == 1]),
                'benign_flows': len(df[df['binary_label'] == 0]),
                'unique_attack_types': df[df['binary_label'] == 1]['attack_type'].nunique(),
                'attack_distribution': df[df['binary_label'] == 1]['attack_type'].value_counts().to_dict()
            }
            
            logger.info(f"Generated network traffic CSV: {output_path}")
            logger.info(f"Statistics: {json.dumps(stats, indent=2)}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate network traffic CSV: {e}")
            return False
    
    def _generate_event_stage_label(self, is_attack: bool, payload: str, record: Dict) -> str:
        """Generate event stage label"""
        if not is_attack:
            return 'benign'
        
        # Extract information from payload
        if not payload or payload == '-':
            return 'unknown_attack'
        
        # Check if there is chain_id and phase information (new field)
        chain_id = record.get('chain_id', '')
        phase = record.get('phase', '')
        
        if chain_id and chain_id != '-':
            # Advanced attack
            if phase and phase != '-':
                return f"{chain_id}_phase{phase}"
            else:
                return chain_id
        
        # Basic attack - use payload as identifier
        if payload.startswith('basic_'):
            return payload
        elif '_' in payload:
            # Try to parse attack type and ID
            parts = payload.split('_')
            if len(parts) >= 2:
                return f"basic_{parts[0]}_{parts[1]}"
        
        return f"attack_{payload}"
    
    def _generate_event_stage_label_from_log(self, is_attack: bool, payload: str, 
                                            chain_id: str, phase: str, attack_type: str, 
                                            event_id: str = '') -> str:
        """Generate event stage label from nginx log"""
        if not is_attack:
            return 'benign'
        
        # Use chain_id as main identifier
        if chain_id and chain_id != '-':
            # For advanced attack, include phase information
            if chain_id.startswith('advanced_'):
                if phase and phase != '-':
                    return f"{chain_id}_phase{phase}"
                else:
                    return chain_id
            # For basic attack
            else:
                return chain_id
        
        # If there is no chain_id, use payload
        if payload and payload != '-':
            return payload
        
        # Finally use attack_type
        if attack_type and attack_type != '-':
            return f"attack_{attack_type}"
        
        return 'unknown_attack'
    
    def _extract_attack_type(self, payload: str) -> str:
        """Extract attack type from payload"""
        if not payload or payload == '-':
            return 'unknown'
        
        # Comprehensive attack type mapping
        attack_types = {
            # Basic attack types
            'sql': 'SQL Injection',
            'xss': 'Cross-Site Scripting', 
            'cmd': 'Command Injection',
            'file': 'File Access',
            'path': 'Path Traversal',
            'auth': 'Authentication Attack',
            'method': 'HTTP Method Attack',
            'api': 'API Attack',
            
            # Extended attack types
            'dir': 'Directory Traversal',
            'directory': 'Directory Traversal',
            'traversal': 'Directory Traversal',
            
            # Authentication and authorization
            'auth_bypass': 'Authentication Bypass',
            'bypass': 'Authentication Bypass',
            'credential': 'Credential Attack',
            'bruteforce': 'Brute Force Attack',
            'brute': 'Brute Force Attack',
            
            # File and information disclosure
            'file_disc': 'File Discovery',
            'disclosure': 'Information Disclosure',
            'info': 'Information Disclosure',
            'enum': 'Enumeration Attack',
            'enumeration': 'Enumeration Attack',
            
            # HTTP method attacks
            'method_enum': 'HTTP Method Enumeration',
            'options': 'HTTP Method Attack',
            'trace': 'HTTP Method Attack',
            'put': 'HTTP Method Attack',
            'delete': 'HTTP Method Attack',
            'patch': 'HTTP Method Attack',
            
            # Advanced attack phases
            'phase1': 'Initial Access',
            'phase2': 'Command & Control',
            'phase3': 'Data Exfiltration', 
            'phase4': 'Lateral Movement',
            
            # Specific advanced techniques
            'c2': 'Command & Control',
            'backdoor': 'Backdoor Installation',
            'persistence': 'Persistence Mechanism',
            'exfiltration': 'Data Exfiltration',
            'exfil': 'Data Exfiltration',
            'lateral': 'Lateral Movement',
            'movement': 'Lateral Movement',
            'pivot': 'Network Pivoting',
            
            # Shell and execution
            'shell': 'Remote Shell',
            'reverse': 'Reverse Shell',
            'bind': 'Bind Shell',
            'exec': 'Code Execution',
            'execution': 'Code Execution',
            'rce': 'Remote Code Execution',
            
            # Network and service attacks
            'smb': 'SMB Attack',
            'ssh': 'SSH Attack',
            'rdp': 'RDP Attack',
            'ftp': 'FTP Attack',
            'dns': 'DNS Attack',
            'http': 'HTTP Attack',
            'https': 'HTTPS Attack',
            
            # Data manipulation
            'upload': 'File Upload Attack',
            'download': 'File Download Attack',
            'compression': 'Data Compression',
            'encoding': 'Data Encoding',
            'obfuscation': 'Code Obfuscation',
            
            # Reconnaissance and scanning
            'recon': 'Reconnaissance',
            'scan': 'Network Scanning',
            'probe': 'Service Probing',
            'fingerprint': 'Fingerprinting',
            
            # Privilege escalation
            'privesc': 'Privilege Escalation',
            'escalation': 'Privilege Escalation',
            'root': 'Root Access Attempt',
            'admin': 'Admin Access Attempt',
            
            # Injection attacks (extended)
            'ldap': 'LDAP Injection',
            'xpath': 'XPath Injection',
            'xml': 'XML Injection',
            'json': 'JSON Injection',
            'nosql': 'NoSQL Injection',
            
            # Web application attacks
            'csrf': 'Cross-Site Request Forgery',
            'ssrf': 'Server-Side Request Forgery',
            'lfi': 'Local File Inclusion',
            'rfi': 'Remote File Inclusion',
            'idor': 'Insecure Direct Object Reference',
            
            # Cryptographic attacks
            'crypto': 'Cryptographic Attack',
            'hash': 'Hash Attack',
            'encryption': 'Encryption Attack',
            'ssl': 'SSL/TLS Attack',
            'tls': 'SSL/TLS Attack'
        }
        
        # Try to extract attack type from payload
        payload_lower = payload.lower()
        
        # First, try exact prefix matching (most accurate)
        parts = payload.split('_')
        if len(parts) > 0:
            # Check for compound attack IDs like "auth_bypass_001"
            if len(parts) >= 2:
                compound_key = f"{parts[0]}_{parts[1]}"
                if compound_key in attack_types:
                    return attack_types[compound_key]
            
            # Check for single prefix like "sql_001"
            if parts[0] in attack_types:
                return attack_types[parts[0]]
        
        # Second, try substring matching for attack type keywords
        # Sort by length (longest first) to match more specific terms first
        sorted_keys = sorted(attack_types.keys(), key=len, reverse=True)
        for key in sorted_keys:
            if key in payload_lower:
                return attack_types[key]
        
        # Third, check for phase-based attacks
        if 'phase' in payload_lower:
            import re
            phase_match = re.search(r'phase(\d+)', payload_lower)
            if phase_match:
                phase_key = f"phase{phase_match.group(1)}"
                if phase_key in attack_types:
                    return attack_types[phase_key]
        
        # If no match found, return 'Other' with more context
        return 'Other'


def process_network_traffic(nginx_csv_path: str, pcap_csv_path: str, output_dir: str) -> bool:
    """Process network traffic data"""
    try:
        generator = NetworkTrafficGenerator()
        
        # Try to load nginx detailed log first (if exists)
        nginx_log_path = nginx_csv_path.replace('/output/', '/logs/').replace('_detailed.csv', '/detailed.log')
        if os.path.exists(nginx_log_path):
            logger.info(f"Loading nginx detailed log: {nginx_log_path}")
            generator.load_nginx_log(nginx_log_path)
        else:
            # Otherwise load CSV
            if not generator.load_nginx_csv(nginx_csv_path):
                return False
        
        if os.path.exists(pcap_csv_path):
            generator.load_pcap_csv(pcap_csv_path)
        
        # Generate network_traffic.csv
        output_path = os.path.join(output_dir, 'network_traffic.csv')
        return generator.generate_network_traffic_csv(output_path)
        
    except Exception as e:
        logger.error(f"Failed to process network traffic: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python network_traffic_generator.py <nginx_csv> <pcap_csv> <output_dir>")
        sys.exit(1)
    
    nginx_csv = sys.argv[1]
    pcap_csv = sys.argv[2]
    output_dir = sys.argv[3]
    
    if not os.path.exists(nginx_csv):
        print(f"Error: Nginx CSV not found: {nginx_csv}")
        sys.exit(1)
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    success = process_network_traffic(nginx_csv, pcap_csv, output_dir)
    sys.exit(0 if success else 1)
