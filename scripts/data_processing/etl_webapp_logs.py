#!/usr/bin/env python3
"""
Web Application Logs ETL Script
Convert login_attempts.log and search_attempts.log to unified JSON Lines format
"""

import os
import json
import re
import argparse
import glob
from datetime import datetime

HOSTNAME = os.uname().nodename

def parse_login_attempts_log(line):
    """Parse login attempts log line"""
    # Format: 2025-07-18 10:37:07 - Login attempt: admin' -- from 172.18.0.5
    pattern = r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - Login attempt: (.+) from (.+)$'
    match = re.match(pattern, line)
    
    if not match:
        return None
    
    timestamp_str, attempt, source_ip = match.groups()
    
    # Parse timestamp
    try:
        dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        timestamp = dt.isoformat() + "Z"
    except:
        timestamp = None
    
    # Determine event type and severity
    event_type = "login_attempt"
    severity = "info"
    is_attack = False
    attack_stage = None
    
    # Check for SQL injection patterns
    if any(pattern in attempt.lower() for pattern in ["'", "union", "select", "or 1=1", "admin'"]):
        event_type = "sql_injection_attempt"
        severity = "warn"
        is_attack = "Exploit"
        attack_stage = "exploit"
    
    # Extract network quintuple information
    network_quintuple = {
        "src_ip": source_ip,
        "src_port": 0,  # Not available in log
        "dst_ip": "0.0.0.0",  # Webapp IP
        "dst_port": 80,  # HTTP port
        "protocol": "HTTP",
        "connection_id": f"http_{source_ip}_0_0.0.0.0_80",
        "connection_state": "ESTABLISHED",
        "session_duration": 0.0
    }
    
    record = {
        "timestamp": timestamp,
        "host": HOSTNAME,
        "source_type": "webapp",
        "event_type": event_type,
        "severity": severity,
        "process": "php",
        "user": None,
        "is_attack": is_attack,
        "attack_stage": attack_stage,
        "details": {
            "raw": line,
            "attempt": attempt,
            "source_ip": source_ip,
            "network_quintuple": network_quintuple
        }
    }
    return record

def parse_search_attempts_log(line):
    """Parse search attempts log line"""
    # Format: 2025-07-18 10:37:18 - Search: ' OR 1=1-- from 172.18.0.5
    pattern = r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - Search: (.+) from (.+)$'
    match = re.match(pattern, line)
    
    if not match:
        return None
    
    timestamp_str, search_term, source_ip = match.groups()
    
    # Parse timestamp
    try:
        dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        timestamp = dt.isoformat() + "Z"
    except:
        timestamp = None
    
    # Determine event type and severity
    event_type = "search_attempt"
    severity = "info"
    is_attack = False
    attack_stage = None
    
    # Check for SQL injection patterns
    if any(pattern in search_term.lower() for pattern in ["'", "union", "select", "or 1=1"]):
        event_type = "sql_injection_attempt"
        severity = "warn"
        is_attack = "Exploit"
        attack_stage = "exploit"
    
    # Extract network quintuple information
    network_quintuple = {
        "src_ip": source_ip,
        "src_port": 0,  # Not available in log
        "dst_ip": "0.0.0.0",  # Webapp IP
        "dst_port": 80,  # HTTP port
        "protocol": "HTTP",
        "connection_id": f"http_{source_ip}_0_0.0.0.0_80",
        "connection_state": "ESTABLISHED",
        "session_duration": 0.0
    }
    
    record = {
        "timestamp": timestamp,
        "host": HOSTNAME,
        "source_type": "webapp",
        "event_type": event_type,
        "severity": severity,
        "process": "php",
        "user": None,
        "is_attack": is_attack,
        "attack_stage": attack_stage,
        "details": {
            "raw": line,
            "search_term": search_term,
            "source_ip": source_ip,
            "network_quintuple": network_quintuple
        }
    }
    return record

def etl_webapp_logs(variant_id=None):
    """ETL webapp logs to JSON Lines format"""
    # Create variant-specific output directory
    if variant_id:
        output_dir = f"data/processed/{variant_id}/webapp_logs"
    else:
        output_dir = "data/processed/webapp_logs"
    os.makedirs(output_dir, exist_ok=True)
    
    # Look for webapp logs in various possible locations
    webapp_logs_found = False
    
    # Check variant-specific webapp logs first
    if variant_id:
        webapp_logs_dir = f"data/logs/{variant_id}/logs"
        if os.path.exists(webapp_logs_dir):
            webapp_logs_found = True
            print(f"Processing webapp logs for variant: {variant_id}")
            
            # Process login_attempts.log
            login_file = os.path.join(webapp_logs_dir, "login_attempts.log")
            if os.path.exists(login_file):
                print(f"Processing login attempts log: {login_file}")
                output_file = os.path.join(output_dir, "login_attempts.jsonl")
                with open(login_file, 'r', encoding='utf-8', errors='ignore') as fin, \
                     open(output_file, 'w', encoding='utf-8') as fout:
                    for line in fin:
                        line = line.strip()
                        if line:
                            record = parse_login_attempts_log(line)
                            if record and variant_id:
                                record["variant_id"] = variant_id
                            if record:
                                fout.write(json.dumps(record, ensure_ascii=False) + '\n')
                print(f"Converted {login_file} to {output_file}")
            
            # Process search_attempts.log
            search_file = os.path.join(webapp_logs_dir, "search_attempts.log")
            if os.path.exists(search_file):
                print(f"Processing search attempts log: {search_file}")
                output_file = os.path.join(output_dir, "search_attempts.jsonl")
                with open(search_file, 'r', encoding='utf-8', errors='ignore') as fin, \
                     open(output_file, 'w', encoding='utf-8') as fout:
                    for line in fin:
                        line = line.strip()
                        if line:
                            record = parse_search_attempts_log(line)
                            if record and variant_id:
                                record["variant_id"] = variant_id
                            if record:
                                fout.write(json.dumps(record, ensure_ascii=False) + '\n')
                print(f"Converted {search_file} to {output_file}")
    
    # Fallback: Check other locations
    if not webapp_logs_found:
        fallback_patterns = [
            "data/logs/*/logs/login_attempts.log",
            "data/logs/*/logs/search_attempts.log",
            "*/logs/login_attempts.log",
            "*/logs/search_attempts.log"
        ]
        
        for pattern in fallback_patterns:
            files = glob.glob(pattern)
            for file_path in files:
                if os.path.exists(file_path):
                    print(f"Processing webapp log: {file_path}")
                    filename = os.path.basename(file_path)
                    output_file = os.path.join(output_dir, f"{filename.replace('.log', '.jsonl')}")
                    
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as fin, \
                         open(output_file, 'w', encoding='utf-8') as fout:
                        for line in fin:
                            line = line.strip()
                            if line:
                                if "login_attempt" in filename:
                                    record = parse_login_attempts_log(line)
                                else:
                                    record = parse_search_attempts_log(line)
                                
                                if record and variant_id:
                                    record["variant_id"] = variant_id
                                if record:
                                    fout.write(json.dumps(record, ensure_ascii=False) + '\n')
                    
                    print(f"Converted {file_path} to {output_file}")
                    webapp_logs_found = True
    
    if not webapp_logs_found:
        print("⚠️  No webapp logs found in expected locations")
        return False
    
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ETL webapp logs")
    parser.add_argument("--variant-id", help="Variant ID to add to records")
    args = parser.parse_args()
    
    etl_webapp_logs(args.variant_id) 