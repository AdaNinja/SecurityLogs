#!/usr/bin/env python3
"""
Attack Logs ETL Script - Fixed Version
Convert attack tool logs and results to unified JSON Lines format
"""

import os
import json
import re
import argparse
import glob
from datetime import datetime
import sys

# Add MITRE mapper
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from mitre_mapper import MITREMapper
except ImportError:
    # Fallback: create a simple mock mapper if module not found
    class MITREMapper:
        def __init__(self):
            pass
        def map_attack_pattern(self, event_type, details, source_type):
            return {
                'technique_id': 'T1190',
                'technique_name': 'Exploit Public-Facing Application'
            }

HOSTNAME = os.uname().nodename

# Initialize MITRE mapper
mitre_mapper = MITREMapper()

def etl_attack_logs(variant_id=None):
    """ETL attack logs to JSON Lines format"""
    # Create variant-specific output directory
    output_dir = f"data/processed/{variant_id}/security_data"
    os.makedirs(output_dir, exist_ok=True)
    
    # Look for attack logs in various possible locations
    attack_logs_found = False
    
    # Check variant-specific attack logs first
    if variant_id:
        attack_log_patterns = [
            f"data/logs/{variant_id}/attacks/container_attack_log.json",
            f"data/logs/{variant_id}/attacks/sql_injection_results.json",
            f"data/logs/{variant_id}/attacks/dns_attacks/dns_attack_results.json",
            f"data/logs/{variant_id}/attacks/*.json",
            f"data/logs/{variant_id}/*.json"
        ]
        
        for pattern in attack_log_patterns:
            files = glob.glob(pattern)
            for file_path in files:
                if os.path.exists(file_path):
                    print(f"Processing attack log: {file_path}")
                    output_file = os.path.join(output_dir, "attack_results.jsonl")
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as fin:
                            data = json.load(fin)
                        
                        with open(output_file, 'w', encoding='utf-8') as fout:
                            if isinstance(data, list):
                                for record in data:
                                    if isinstance(record, dict):
                                        # Add variant_id if not present
                                        if variant_id and "variant_id" not in record:
                                            record["variant_id"] = variant_id
                                        fout.write(json.dumps(record, ensure_ascii=False) + '\n')
                            elif isinstance(data, dict):
                                # Check if this is an attack_results file with nested data
                                if 'custom_tests' in data:
                                    # This is an attack_results file - expand nested attacks
                                    variant_id = data.get('variant_id', variant_id)
                                    
                                    # Expand login injections
                                    for i, injection in enumerate(data.get('custom_tests', {}).get('login_injections', [])):
                                        # Normalize timestamp format
                                        timestamp = injection.get('timestamp', '')
                                        if timestamp and not timestamp.endswith('Z'):
                                            timestamp = timestamp + 'Z'
                                        
                                        attack_record = {
                                            'variant_id': variant_id,
                                            'attack_type': 'login_injection',
                                            'attack_index': i,
                                            'payload': injection.get('payload', ''),
                                            'status_code': injection.get('status_code', ''),
                                            'response_length': injection.get('response_length', ''),
                                            'response_time': injection.get('response_time', ''),
                                            'timestamp': timestamp,
                                            'sql_error': injection.get('sql_error', ''),
                                            'success': injection.get('success', ''),
                                            'source_type': 'attack_logs',
                                            'event_type': 'sql_injection',
                                            'severity': 'high' if injection.get('success', False) else 'medium'
                                        }
                                        fout.write(json.dumps(attack_record, ensure_ascii=False) + '\n')
                                    
                                    # Expand search injections
                                    for i, injection in enumerate(data.get('custom_tests', {}).get('search_injections', [])):
                                        # Normalize timestamp format
                                        timestamp = injection.get('timestamp', '')
                                        if timestamp and not timestamp.endswith('Z'):
                                            timestamp = timestamp + 'Z'
                                        
                                        attack_record = {
                                            'variant_id': variant_id,
                                            'attack_type': 'search_injection',
                                            'attack_index': i,
                                            'payload': injection.get('payload', ''),
                                            'status_code': injection.get('status_code', ''),
                                            'response_length': injection.get('response_length', ''),
                                            'response_time': injection.get('response_time', ''),
                                            'timestamp': timestamp,
                                            'sql_error': injection.get('sql_error', False),
                                            'success': injection.get('success', True),
                                            'time_based': injection.get('time_based', False),
                                            'source_type': 'attack_logs',
                                            'event_type': 'sql_injection',
                                            'severity': 'high' if not injection.get('sql_error', False) else 'medium'
                                        }
                                        fout.write(json.dumps(attack_record, ensure_ascii=False) + '\n')
                                    
                                    # Expand union injections
                                    for i, injection in enumerate(data.get('custom_tests', {}).get('union_injections', [])):
                                        # Normalize timestamp format
                                        timestamp = injection.get('timestamp', '')
                                        if timestamp and not timestamp.endswith('Z'):
                                            timestamp = timestamp + 'Z'
                                        
                                        attack_record = {
                                            'variant_id': variant_id,
                                            'attack_type': 'union_injection',
                                            'attack_index': i,
                                            'payload': injection.get('payload', ''),
                                            'status_code': injection.get('status_code', ''),
                                            'response_length': injection.get('response_length', ''),
                                            'response_time': injection.get('response_time', ''),
                                            'timestamp': timestamp,
                                            'sql_error': injection.get('sql_error', False),
                                            'success': injection.get('success', True),
                                            'source_type': 'attack_logs',
                                            'event_type': 'sql_injection',
                                            'severity': 'high' if not injection.get('sql_error', False) else 'medium'
                                        }
                                        fout.write(json.dumps(attack_record, ensure_ascii=False) + '\n')
                                    
                                    # Expand time-based injections
                                    for i, injection in enumerate(data.get('custom_tests', {}).get('time_based_injections', [])):
                                        # Normalize timestamp format
                                        timestamp = injection.get('timestamp', '')
                                        if timestamp and not timestamp.endswith('Z'):
                                            timestamp = timestamp + 'Z'
                                        
                                        attack_record = {
                                            'variant_id': variant_id,
                                            'attack_type': 'time_based_injection',
                                            'attack_index': i,
                                            'payload': injection.get('payload', ''),
                                            'status_code': injection.get('status_code', ''),
                                            'response_time': injection.get('response_time', ''),
                                            'timestamp': timestamp,
                                            'sql_error': injection.get('sql_error', False),
                                            'time_based': injection.get('time_based', True),
                                            'source_type': 'attack_logs',
                                            'event_type': 'sql_injection',
                                            'severity': 'high' if injection.get('time_based', False) else 'medium'
                                        }
                                        fout.write(json.dumps(attack_record, ensure_ascii=False) + '\n')
                                    
                                    # Expand DNS attacks if present
                                    if 'dns_attacks' in data:
                                        dns_attacks = data['dns_attacks']
                                        
                                        # Process DNS reconnaissance
                                        if 'dns_reconnaissance' in dns_attacks:
                                            recon = dns_attacks['dns_reconnaissance']
                                            for i, subdomain in enumerate(recon.get('discovered_subdomains', [])):
                                                dns_record = {
                                                    'variant_id': variant_id,
                                                    'attack_type': 'dns_reconnaissance',
                                                    'attack_index': i,
                                                    'subdomain': subdomain.get('subdomain', ''),
                                                    'ip': subdomain.get('ip', ''),
                                                    'record_type': subdomain.get('record_type', 'A'),
                                                    'timestamp': subdomain.get('timestamp', ''),
                                                    'source_type': 'attack_logs',
                                                    'event_type': 'dns_reconnaissance',
                                                    'severity': 'medium',
                                                    'attack_stage': 'reconnaissance'
                                                }
                                                fout.write(json.dumps(dns_record, ensure_ascii=False) + '\n')
                                        
                                        # Process DNS brute force
                                        if 'dns_brute_force' in dns_attacks:
                                            brute = dns_attacks['dns_brute_force']
                                            for i, subdomain in enumerate(brute.get('discovered', [])):
                                                dns_record = {
                                                    'variant_id': variant_id,
                                                    'attack_type': 'dns_brute_force',
                                                    'attack_index': i,
                                                    'subdomain': subdomain,
                                                    'attempts': brute.get('attempts', 0),
                                                    'timestamp': brute.get('timestamp', ''),
                                                    'source_type': 'attack_logs',
                                                    'event_type': 'dns_brute_force',
                                                    'severity': 'medium',
                                                    'attack_stage': 'reconnaissance'
                                                }
                                                fout.write(json.dumps(dns_record, ensure_ascii=False) + '\n')
                                        
                                        # Process DNS tunneling
                                        if 'dns_tunneling' in dns_attacks:
                                            for i, tunnel in enumerate(dns_attacks['dns_tunneling']):
                                                dns_record = {
                                                    'variant_id': variant_id,
                                                    'attack_type': 'dns_tunneling',
                                                    'attack_index': i,
                                                    'technique': tunnel.get('technique', ''),
                                                    'payload': tunnel.get('payload', ''),
                                                    'chunks_sent': tunnel.get('chunks_sent', 0),
                                                    'success': tunnel.get('success', False),
                                                    'timestamp': tunnel.get('timestamp', ''),
                                                    'source_type': 'attack_logs',
                                                    'event_type': 'dns_tunneling',
                                                    'severity': 'high',
                                                    'attack_stage': 'exfiltration'
                                                }
                                                fout.write(json.dumps(dns_record, ensure_ascii=False) + '\n')
                                        
                                        # Process data exfiltration
                                        if 'data_exfiltration' in dns_attacks:
                                            exfil = dns_attacks['data_exfiltration']
                                            dns_record = {
                                                'variant_id': variant_id,
                                                'attack_type': 'data_exfiltration',
                                                'method': exfil.get('method', ''),
                                                'data_type': exfil.get('data_type', ''),
                                                'records_exfiltrated': exfil.get('records_exfiltrated', 0),
                                                'success': exfil.get('success', False),
                                                'timestamp': exfil.get('timestamp', ''),
                                                'source_type': 'attack_logs',
                                                'event_type': 'data_exfiltration',
                                                'severity': 'critical',
                                                'attack_stage': 'exfiltration'
                                            }
                                            fout.write(json.dumps(dns_record, ensure_ascii=False) + '\n')
                                    
                                    print(f"Expanded nested attack data from {file_path}")
                                elif 'dns_reconnaissance' in data or 'dns_brute_force' in data or 'data_exfiltration' in data:
                                    # This is a DNS attack results file - expand DNS attacks
                                    variant_id = data.get('variant_id', variant_id)
                                    
                                    # Process DNS reconnaissance
                                    if 'dns_reconnaissance' in data:
                                        recon = data['dns_reconnaissance']
                                        for i, subdomain in enumerate(recon.get('discovered_subdomains', [])):
                                            dns_record = {
                                                'variant_id': variant_id,
                                                'attack_type': 'dns_reconnaissance',
                                                'attack_index': i,
                                                'subdomain': subdomain.get('subdomain', ''),
                                                'ip': subdomain.get('ip', ''),
                                                'record_type': subdomain.get('record_type', 'A'),
                                                'timestamp': subdomain.get('timestamp', ''),
                                                'source_type': 'attack_logs',
                                                'event_type': 'dns_reconnaissance',
                                                'severity': 'medium',
                                                'attack_stage': 'reconnaissance'
                                            }
                                            fout.write(json.dumps(dns_record, ensure_ascii=False) + '\n')
                                    
                                    # Process DNS brute force
                                    if 'dns_brute_force' in data:
                                        brute = data['dns_brute_force']
                                        # Create a record for the brute force attempt
                                        dns_record = {
                                            'variant_id': variant_id,
                                            'attack_type': 'dns_brute_force',
                                            'attack_index': 0,
                                            'target_domain': brute.get('target_domain', ''),
                                            'attempts': brute.get('attempts', 0),
                                            'discovered_count': len(brute.get('discovered', [])),
                                            'timestamp': brute.get('timestamp', ''),
                                            'source_type': 'attack_logs',
                                            'event_type': 'dns_brute_force',
                                            'severity': 'medium',
                                            'attack_stage': 'reconnaissance'
                                        }
                                        fout.write(json.dumps(dns_record, ensure_ascii=False) + '\n')
                                    
                                    # Process data exfiltration
                                    if 'data_exfiltration' in data:
                                        exfil = data['data_exfiltration']
                                        # Create records for each exfiltration chunk
                                        for i, chunk in enumerate(exfil.get('exfiltration_results', [])):
                                            dns_record = {
                                                'variant_id': variant_id,
                                                'attack_type': 'dns_data_exfiltration',
                                                'attack_index': i,
                                                'chunk_id': chunk.get('chunk_id', i+1),
                                                'total_chunks': chunk.get('total_chunks', 0),
                                                'query': chunk.get('query', ''),
                                                'success': chunk.get('success', False),
                                                'error': chunk.get('error', ''),
                                                'timestamp': chunk.get('timestamp', ''),
                                                'source_type': 'attack_logs',
                                                'event_type': 'dns_data_exfiltration',
                                                'severity': 'critical',
                                                'attack_stage': 'exfiltration'
                                            }
                                            fout.write(json.dumps(dns_record, ensure_ascii=False) + '\n')
                                    
                                    print(f"Expanded DNS attack data from {file_path}")
                                else:
                                    # Regular record
                                    if variant_id and "variant_id" not in data:
                                        data["variant_id"] = variant_id
                                    fout.write(json.dumps(data, ensure_ascii=False) + '\n')
                        
                        print(f"Converted {file_path} to {output_file}")
                        attack_logs_found = True
                        
                    except json.JSONDecodeError as e:
                        print(f"Error parsing JSON from {file_path}: {e}")
                    except Exception as e:
                        print(f"Error processing {file_path}: {e}")
    
    if not attack_logs_found:
        print("⚠️  No attack logs found")
        return True  # Not an error, just no data
    
    return True

def main():
    parser = argparse.ArgumentParser(description="ETL attack logs")
    parser.add_argument("--variant-id", help="Variant ID")
    
    args = parser.parse_args()
    
    success = etl_attack_logs(args.variant_id)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 