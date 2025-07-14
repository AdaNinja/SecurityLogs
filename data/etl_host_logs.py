#!/usr/bin/env python3
"""
Host Logs ETL Script
Convert host system logs to unified JSON Lines format
"""

import os
import json
import re
from datetime import datetime

HOSTNAME = os.uname().nodename

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
    
    return {
        "timestamp": timestamp,
        "host": HOSTNAME,
        "source_type": "syslog",
        "event_type": event_type,
        "severity": severity,
        "process": service,
        "user": None,
        "is_attack": None,
        "details": {
            "raw": line,
            "service": service,
            "message": message
        }
    }

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
    
    return {
        "timestamp": timestamp,
        "host": HOSTNAME,
        "source_type": "auth_log",
        "event_type": event_type,
        "severity": severity,
        "process": service,
        "user": None,
        "is_attack": None,
        "details": {
            "raw": line,
            "service": service,
            "message": message
        }
    }

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
    
    return {
        "timestamp": timestamp,
        "host": HOSTNAME,
        "source_type": "kernel_log",
        "event_type": event_type,
        "severity": severity,
        "process": "kernel",
        "user": None,
        "is_attack": None,
        "details": {
            "raw": line,
            "message": message
        }
    }

def etl_host_logs():
    """ETL host logs to JSON Lines format"""
    output_dir = "host_logs"
    os.makedirs(output_dir, exist_ok=True)
    
    # Look for host logs in any variant directory
    host_logs_found = False
    
    for variant_dir in os.listdir("data/logs"):
        host_dir = f"data/logs/{variant_dir}/host"
        if os.path.exists(host_dir):
            host_logs_found = True
            print(f"Processing host logs from variant: {variant_dir}")
            
            # Process syslog
            syslog_file = os.path.join(host_dir, "syslog")
            if os.path.exists(syslog_file):
                print(f"Processing syslog: {syslog_file}")
                output_file = os.path.join(output_dir, f"{variant_dir}_syslog.jsonl")
                with open(syslog_file, 'r', encoding='utf-8', errors='ignore') as fin, \
                     open(output_file, 'w', encoding='utf-8') as fout:
                    for line in fin:
                        line = line.strip()
                        if line:
                            record = parse_syslog_line(line)
                            if record:
                                fout.write(json.dumps(record, ensure_ascii=False) + '\n')
                print(f"Converted syslog to {output_file}")
            
            # Process auth.log
            auth_file = os.path.join(host_dir, "auth.log")
            if os.path.exists(auth_file):
                print(f"Processing auth.log: {auth_file}")
                output_file = os.path.join(output_dir, f"{variant_dir}_auth.jsonl")
                with open(auth_file, 'r', encoding='utf-8', errors='ignore') as fin, \
                     open(output_file, 'w', encoding='utf-8') as fout:
                    for line in fin:
                        line = line.strip()
                        if line:
                            record = parse_auth_log_line(line)
                            if record:
                                fout.write(json.dumps(record, ensure_ascii=False) + '\n')
                print(f"Converted auth.log to {output_file}")
            
            # Process kern.log
            kern_file = os.path.join(host_dir, "kern.log")
            if os.path.exists(kern_file):
                print(f"Processing kern.log: {kern_file}")
                output_file = os.path.join(output_dir, f"{variant_dir}_kernel.jsonl")
                with open(kern_file, 'r', encoding='utf-8', errors='ignore') as fin, \
                     open(output_file, 'w', encoding='utf-8') as fout:
                    for line in fin:
                        line = line.strip()
                        if line:
                            record = parse_kern_log_line(line)
                            if record:
                                fout.write(json.dumps(record, ensure_ascii=False) + '\n')
                print(f"Converted kern.log to {output_file}")
    
    if not host_logs_found:
        print("No host logs found in any variant directory")

if __name__ == "__main__":
    etl_host_logs() 