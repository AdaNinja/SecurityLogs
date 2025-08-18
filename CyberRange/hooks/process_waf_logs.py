#!/usr/bin/env python3
"""
Process WAF Logs Hook
Converts ModSecurity access.log to detailed.log format for compatibility with existing parsers
"""

import os
import sys
import re
import json
import logging
from pathlib import Path
from datetime import datetime

def setup_logging():
    """Setup logging for the hook"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

def generate_detailed_log():
    """Generate detailed.log from access.log and ModSecurity audit.log"""
    logger = setup_logging()
    
    logger.info("Generating detailed log from ModSecurity logs")
    
    # Get experiment directory from environment
    experiment_dir = os.environ.get('EXPERIMENT_DIR', 'logs')
    
    # Input files
    access_log_path = Path(experiment_dir) / 'nginx' / 'access.log'
    audit_log_path = Path(experiment_dir) / 'modsecurity' / 'audit.log'
    
    # Output file
    detailed_log_path = Path(experiment_dir) / 'nginx' / 'detailed.log'
    
    if not access_log_path.exists():
        logger.warning(f"Access log not found: {access_log_path}")
        return False
    
    # Parse audit log for attack information
    attack_info = {}
    if audit_log_path.exists():
        try:
            with open(audit_log_path, 'r') as f:
                for line in f:
                    try:
                        audit_data = json.loads(line.strip())
                        transaction = audit_data.get('transaction', {})
                        request = transaction.get('request', {})
                        
                        # Extract request details
                        method = request.get('method', '')
                        uri = request.get('uri', '')
                        client_ip = transaction.get('client_ip', '')
                        timestamp = transaction.get('time_stamp', '')
                        
                        # Check if this was an attack
                        messages = transaction.get('messages', [])
                        is_attack = len(messages) > 0
                        attack_type = 'unknown'
                        
                        # Determine attack type from messages
                        for message in messages:
                            msg_text = message.get('message', '').lower()
                            if 'sql injection' in msg_text:
                                attack_type = 'sql_injection'
                                break
                            elif 'xss' in msg_text or 'cross site' in msg_text:
                                attack_type = 'xss'
                                break
                            elif 'traversal' in msg_text:
                                attack_type = 'directory_traversal'
                                break
                        
                        # Create key for matching with access log
                        key = f"{client_ip}_{method}_{uri}"
                        attack_info[key] = {
                            'is_attack': is_attack,
                            'attack_type': attack_type,
                            'timestamp': timestamp,
                            'waf_action': 'blocked' if is_attack else 'allowed'
                        }
                        
                    except json.JSONDecodeError:
                        continue
                        
        except Exception as e:
            logger.warning(f"Failed to parse audit log: {e}")
    
    # Process access log and generate detailed log
    try:
        with open(access_log_path, 'r') as access_file, open(detailed_log_path, 'w') as detailed_file:
            for line in access_file:
                # Parse standard nginx access log format
                # Format: IP - - [timestamp] "method path HTTP/1.1" status size "referer" "user_agent" "forwarded"
                match = re.match(
                    r'^(\S+) - (\S+) \[([^\]]+)\] "(\S+) ([^"]*) HTTP/[^"]*" (\d+) (\d+) "([^"]*)" "([^"]*)"',
                    line.strip()
                )
                
                if match:
                    ip, user, timestamp, method, path, status, size, referer, user_agent = match.groups()
                    
                    # Look for attack information
                    key = f"{ip}_{method}_{path.split('?')[0]}"  # Remove query params for matching
                    attack_data = attack_info.get(key, {})
                    
                    # Generate attack headers based on status and attack info
                    if attack_data.get('is_attack', False) or status == '403':
                        attack_id = f"attack_{int(datetime.now().timestamp())}"
                        payload_id = f"payload_{hash(path) % 1000}"
                        traffic_type = "attack"
                        attack_type = attack_data.get('attack_type', 'unknown')
                        source_ip = ip
                        timestamp_iso = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                    else:
                        attack_id = "-"
                        payload_id = "-"
                        traffic_type = "benign"
                        attack_type = "-"
                        source_ip = ip
                        timestamp_iso = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                    
                    # Generate detailed log line
                    detailed_line = f'{ip} - {user} [{timestamp}] "{method} {path} HTTP/1.1" {status} {size} "{referer}" "{user_agent}" "{attack_id}" "{payload_id}" "{timestamp_iso}" "{source_ip}" "{traffic_type}" "{attack_type}"\n'
                    detailed_file.write(detailed_line)
                else:
                    # If parsing fails, write original line
                    detailed_file.write(line)
        
        logger.info(f"Generated detailed log: {detailed_log_path}")
        
        # Log statistics
        access_lines = sum(1 for _ in open(access_log_path))
        detailed_lines = sum(1 for _ in open(detailed_log_path))
        attack_count = len([k for k, v in attack_info.items() if v.get('is_attack', False)])
        
        logger.info(f"Processed {access_lines} access log entries")
        logger.info(f"Generated {detailed_lines} detailed log entries")
        logger.info(f"Detected {attack_count} attack entries")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to generate detailed log: {e}")
        return False

def main():
    """Main function"""
    success = generate_detailed_log()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
