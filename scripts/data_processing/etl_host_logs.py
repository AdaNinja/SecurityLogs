#!/usr/bin/env python3
"""
ETL Host Logs
Process host logs to JSON Lines format
"""

import os
import json
import re
import argparse
import glob
from datetime import datetime
from typing import Dict, Any, List
# Fix relative import issue
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from config import get_config

HOSTNAME = os.uname().nodename

def is_attack_event(message: str) -> bool:
    """Determine if syslog message indicates an attack"""
    attack_keywords = [
        'sql injection', 'xss', 'csrf', 'buffer overflow', 'privilege escalation',
        'brute force', 'dictionary attack', 'port scan', 'nmap', 'sqlmap',
        'unauthorized access', 'intrusion', 'malware', 'virus', 'trojan'
    ]
    message_lower = message.lower()
    return any(keyword in message_lower for keyword in attack_keywords)

def determine_attack_stage(message: str) -> str | None:
    """Determine attack stage based on syslog message"""
    if is_attack_event(message):
        message_lower = message.lower()
        if any(word in message_lower for word in ['scan', 'nmap', 'port']):
            return "reconnaissance"
        elif any(word in message_lower for word in ['injection', 'exploit', 'attack']):
            return "exploit"
        elif any(word in message_lower for word in ['data', 'extract', 'dump']):
            return "exfiltration"
        else:
            return "exploit"
    return None

def parse_syslog_line(line):
    """Parse syslog line"""
    # Syslog format: timestamp hostname service[pid]: message
    pattern = r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)'
    match = re.match(pattern, line)
    
    if not match:
        return None
    
    timestamp_str, hostname, service, message = match.groups()
    
    # Parse timestamp
    try:
        year = datetime.now().year
        dt = datetime.strptime(f"{year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        timestamp = dt.isoformat() + "Z"
    except:
        timestamp = None
    
    # Determine event type and severity
    event_type = "system_log"
    severity = "info"
    
    if "error" in message.lower():
        severity = "error"
        event_type = "system_error"
    elif "warning" in message.lower():
        severity = "warn"
        event_type = "system_warning"
    elif "auth" in service.lower():
        event_type = "authentication"
    elif "kernel" in service.lower():
        event_type = "kernel_log"
    
    record = {
        "timestamp": timestamp,
        "host": HOSTNAME,
        "source_type": "syslog",
        "event_type": event_type,
        "severity": severity,
        "process": service,
        "user": None,
        "is_attack": is_attack_event(message),
        "attack_stage": determine_attack_stage(message),
        "details": {
            "raw": line,
            "service": service,
            "message": message
        }
    }
    return record

def parse_auth_log_line(line):
    """Parse auth.log line"""
    # Auth log format: timestamp service[pid]: message
    pattern = r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)'
    match = re.match(pattern, line)
    
    if not match:
        return None
    
    timestamp_str, hostname, service, message = match.groups()
    
    # Parse timestamp
    try:
        year = datetime.now().year
        dt = datetime.strptime(f"{year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        timestamp = dt.isoformat() + "Z"
    except:
        timestamp = None
    
    # Determine event type
    event_type = "authentication"
    severity = "info"
    
    if "failed" in message.lower():
        severity = "warn"
        event_type = "auth_failure"
    elif "success" in message.lower():
        event_type = "auth_success"
    elif "invalid" in message.lower():
        severity = "warn"
        event_type = "auth_invalid"
    
    record = {
        "timestamp": timestamp,
        "host": HOSTNAME,
        "source_type": "auth_log",
        "event_type": event_type,
        "severity": severity,
        "process": service,
        "user": None,
        "is_attack": False,  # Authentication logs default to non-attack
        "attack_stage": None,
        "details": {
            "raw": line,
            "service": service,
            "message": message
        }
    }
    return record

def parse_kern_log_line(line):
    """Parse kernel log line"""
    # Kernel log format: timestamp kernel: message
    pattern = r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:\s*(.*)'
    match = re.match(pattern, line)
    
    if not match:
        return None
    
    timestamp_str, hostname, message = match.groups()
    
    # Parse timestamp
    try:
        year = datetime.now().year
        dt = datetime.strptime(f"{year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        timestamp = dt.isoformat() + "Z"
    except:
        timestamp = None
    
    # Determine event type
    event_type = "kernel_log"
    severity = "info"
    
    if "error" in message.lower():
        severity = "error"
        event_type = "kernel_error"
    elif "warning" in message.lower():
        severity = "warn"
        event_type = "kernel_warning"
    
    record = {
        "timestamp": timestamp,
        "host": HOSTNAME,
        "source_type": "kernel_log",
        "event_type": event_type,
        "severity": severity,
        "process": "kernel",
        "user": None,
        "is_attack": False,  # Kernel logs default to non-attack
        "attack_stage": None,
        "details": {
            "raw": line,
            "message": message
        }
    }
    return record

def etl_host_logs(variant_id: str = None) -> bool:
    """ETL host logs to JSON Lines format"""
    print(f"🚀 Processing host logs for variant: {variant_id}")
    
    config = get_config(variant_id)
    output_dir = config.system_logs_data_dir
    os.makedirs(output_dir, exist_ok=True)
    
    # Look for host logs in various possible locations
    host_logs_found = False
    
    # Check data/logs/ for variant-specific host logs
    if variant_id and os.path.exists(f"data/logs/{variant_id}"):
        host_logs_found = True
        print(f"Processing host logs for variant: {variant_id}")
        
        # Process system logs from variant directory
        variant_logs_dir = f"data/logs/{variant_id}"
        
        # Process syslog
        syslog_file = os.path.join(variant_logs_dir, "syslog")
        if os.path.exists(syslog_file) and os.path.getsize(syslog_file) > 0:
            print(f"Processing syslog: {syslog_file}")
            output_file = os.path.join(output_dir, f"{variant_id}_syslog.jsonl")
            with open(syslog_file, 'r', encoding='utf-8', errors='ignore') as fin, \
                 open(output_file, 'w', encoding='utf-8') as fout:
                for line in fin:
                    line = line.strip()
                    if line:
                        record = parse_syslog_line(line)
                        if record and variant_id:
                            record["variant_id"] = variant_id
                        if record:
                            fout.write(json.dumps(record, ensure_ascii=False) + '\n')
            print(f"Converted syslog to {output_file}")
        
        # Process messages
        messages_file = os.path.join(variant_logs_dir, "messages")
        if os.path.exists(messages_file) and os.path.getsize(messages_file) > 0:
            print(f"Processing messages: {messages_file}")
            output_file = os.path.join(output_dir, f"{variant_id}_messages.jsonl")
            with open(messages_file, 'r', encoding='utf-8', errors='ignore') as fin, \
                 open(output_file, 'w', encoding='utf-8') as fout:
                for line in fin:
                    line = line.strip()
                    if line:
                        record = parse_syslog_line(line)
                        if record and variant_id:
                            record["variant_id"] = variant_id
                        if record:
                            fout.write(json.dumps(record, ensure_ascii=False) + '\n')
            print(f"Converted messages to {output_file}")
        
        # Process user.log
        user_log_file = os.path.join(variant_logs_dir, "user.log")
        if os.path.exists(user_log_file) and os.path.getsize(user_log_file) > 0:
            print(f"Processing user.log: {user_log_file}")
            output_file = os.path.join(output_dir, f"{variant_id}_user.jsonl")
            with open(user_log_file, 'r', encoding='utf-8', errors='ignore') as fin, \
                 open(output_file, 'w', encoding='utf-8') as fout:
                for line in fin:
                    line = line.strip()
                    if line:
                        record = parse_syslog_line(line)
                        if record and variant_id:
                            record["variant_id"] = variant_id
                        if record:
                            fout.write(json.dumps(record, ensure_ascii=False) + '\n')
            print(f"Converted user.log to {output_file}")
        
        # Process php7.4-fpm.log
        php_fpm_file = os.path.join(variant_logs_dir, "php7.4-fpm.log")
        if os.path.exists(php_fpm_file) and os.path.getsize(php_fpm_file) > 0:
            print(f"Processing php7.4-fpm.log: {php_fpm_file}")
            output_file = os.path.join(output_dir, f"{variant_id}_php_fpm.jsonl")
            with open(php_fpm_file, 'r', encoding='utf-8', errors='ignore') as fin, \
                 open(output_file, 'w', encoding='utf-8') as fout:
                for line in fin:
                    line = line.strip()
                    if line:
                        record = parse_syslog_line(line)
                        if record and variant_id:
                            record["variant_id"] = variant_id
                        if record:
                            fout.write(json.dumps(record, ensure_ascii=False) + '\n')
            print(f"Converted php7.4-fpm.log to {output_file}")
    
    # Fallback: Check data/raw/ for host logs (legacy support)
    if not host_logs_found and os.path.exists("data/raw"):
        for subdir in os.listdir("data/raw"):
            host_dir = f"data/raw/{subdir}/host"
            if os.path.exists(host_dir):
                host_logs_found = True
                print(f"Processing host logs from: {subdir}")
                
                # Process syslog
                syslog_file = os.path.join(host_dir, "syslog")
                if os.path.exists(syslog_file):
                    print(f"Processing syslog: {syslog_file}")
                    output_file = os.path.join(output_dir, f"{subdir}_syslog.jsonl")
                    with open(syslog_file, 'r', encoding='utf-8', errors='ignore') as fin, \
                         open(output_file, 'w', encoding='utf-8') as fout:
                        for line in fin:
                            line = line.strip()
                            if line:
                                record = parse_syslog_line(line)
                                if record and variant_id:
                                    record["variant_id"] = variant_id
                                if record:
                                    fout.write(json.dumps(record, ensure_ascii=False) + '\n')
                    print(f"Converted syslog to {output_file}")
                
                # Process auth.log
                auth_file = os.path.join(host_dir, "auth.log")
                if os.path.exists(auth_file):
                    print(f"Processing auth.log: {auth_file}")
                    output_file = os.path.join(output_dir, f"{subdir}_auth.jsonl")
                    with open(auth_file, 'r', encoding='utf-8', errors='ignore') as fin, \
                         open(output_file, 'w', encoding='utf-8') as fout:
                        for line in fin:
                            line = line.strip()
                            if line:
                                record = parse_auth_log_line(line)
                                if record and variant_id:
                                    record["variant_id"] = variant_id
                                if record:
                                    fout.write(json.dumps(record, ensure_ascii=False) + '\n')
                    print(f"Converted auth.log to {output_file}")
    
    if not host_logs_found:
        print("⚠️  No host logs found in expected locations")
        return False
    
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ETL host logs")
    parser.add_argument("--variant-id", help="Variant ID to add to records")
    args = parser.parse_args()
    
    etl_host_logs(args.variant_id) 