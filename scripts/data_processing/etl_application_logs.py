#!/usr/bin/env python3
"""
Application Logs ETL Script
Convert Nginx, PHP, and other application logs to unified JSON Lines format
"""

import os
import json
import re
import argparse
import glob
from datetime import datetime

HOSTNAME = os.uname().nodename

def parse_nginx_access_log(line):
    """Parse Nginx access log line"""
    # Nginx access log format: IP - - [timestamp] "method path protocol" status size "referer" "user-agent"
    pattern = r'^([^ ]+) - - \[([^\]]+)\] "([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)"'
    match = re.match(pattern, line)
    
    if not match:
        return None
    
    ip, timestamp_str, request, status, size, referer, user_agent = match.groups()
    
    # Parse timestamp
    try:
        dt = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
        timestamp = dt.isoformat()
    except:
        timestamp = None
    
    # Parse request
    method, path, protocol = request.split(' ', 2) if ' ' in request else (None, None, None)
    
    # Determine event type
    event_type = "http_request"
    if status.startswith('4'):
        event_type = "http_error_4xx"
    elif status.startswith('5'):
        event_type = "http_error_5xx"
    
    # Determine severity
    severity = "info"
    if status.startswith('4') or status.startswith('5'):
        severity = "warn"
    
    # Check for attack patterns
    is_attack = None
    if path and any(pattern in path.lower() for pattern in ['union', 'select', 'or 1=1', 'admin\'', '\'--']):
        is_attack = "Exploit"
        event_type = "sql_injection_attempt"
    
    # Extract network quintuple information
    network_quintuple = {
        "src_ip": ip,
        "src_port": 0,  # Nginx logs don't typically include source port
        "dst_ip": "0.0.0.0",  # Will be filled by webapp IP
        "dst_port": 80,  # Default HTTP port
        "protocol": "HTTP",
        "connection_id": f"http_{ip}_0_0.0.0.0_80",
        "connection_state": "ESTABLISHED",
        "session_duration": 0.0
    }
    
    # Try to extract port from path or referer
    if path and ':' in path:
        port_match = re.search(r':(\d+)', path)
        if port_match:
            network_quintuple["dst_port"] = int(port_match.group(1))
    
    # Update connection ID with actual port
    network_quintuple["connection_id"] = f"http_{ip}_0_0.0.0.0_{network_quintuple['dst_port']}"
    
    record = {
        "timestamp": timestamp,
        "host": HOSTNAME,
        "source_type": "nginx_access",
        "event_type": event_type,
        "severity": severity,
        "process": "nginx",
        "user": None,
        "is_attack": bool(is_attack),  # 转换为布尔值
        "attack_stage": "exploit" if is_attack else None,
        "network_quintuple": network_quintuple,
        "details": {
            "raw": line,
            "ip": ip,
            "method": method,
            "path": path,
            "status": status,
            "size": size,
            "referer": referer,
            "user_agent": user_agent
        }
    }
    return record

def parse_nginx_error_log(line):
    """Parse Nginx error log line"""
    # Nginx error log format: [timestamp] [level] [pid] [message]
    pattern = r'^\[([^\]]+)\] ([^:]+): (\d+)#\d+: \*(.*)'
    match = re.match(pattern, line)
    
    if not match:
        return None
    
    timestamp_str, level, pid, message = match.groups()
    
    # Parse timestamp
    try:
        dt = datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S")
        timestamp = dt.isoformat() + "Z"
    except:
        timestamp = None
    
    # Map level to severity
    severity_map = {
        "emerg": "error",
        "alert": "error", 
        "crit": "error",
        "error": "error",
        "warn": "warn",
        "notice": "info",
        "info": "info",
        "debug": "debug"
    }
    severity = severity_map.get(level, "info")
    
    record = {
        "timestamp": timestamp,
        "host": HOSTNAME,
        "source_type": "nginx_error",
        "event_type": "error",
        "severity": severity,
        "process": "nginx",
        "user": None,
        "is_attack": None,
        "attack_stage": None,
        "details": {
            "raw": line,
            "level": level,
            "pid": pid,
            "message": message
        }
    }
    return record

def parse_php_log(line):
    """Parse PHP-FPM log line"""
    # PHP log format varies, try common patterns
    patterns = [
        r'\[([^\]]+)\] (ERROR|WARNING|INFO): (.*)',
        r'([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8}) (ERROR|WARNING|INFO): (.*)'
    ]
    
    for pattern in patterns:
        match = re.match(pattern, line)
        if match:
            timestamp_str, level, message = match.groups()
            
            # Parse timestamp
            try:
                if 'T' in timestamp_str:
                    dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                else:
                    dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                timestamp = dt.isoformat() + "Z"
            except:
                timestamp = None
            
            # Map level to severity
            severity = "info"
            if level == "ERROR":
                severity = "error"
            elif level == "WARNING":
                severity = "warn"
            
            record = {
                "timestamp": timestamp,
                "host": HOSTNAME,
                "source_type": "php_fpm",
                "event_type": "php_error",
                "severity": severity,
                "process": "php-fpm",
                "user": None,
                "is_attack": None,
                "attack_stage": None,
                "details": {
                    "raw": line,
                    "level": level,
                    "message": message
                }
            }
            return record
    
    # Fallback for unparseable lines
    record = {
        "timestamp": None,
        "host": HOSTNAME,
        "source_type": "php_fpm",
        "event_type": "php_log",
        "severity": "info",
        "process": "php-fpm",
        "user": None,
        "is_attack": None,
        "attack_stage": None,
        "details": {"raw": line}
    }
    return record

def etl_application_logs(variant_id=None):
    """ETL application logs to JSON Lines format"""
    # Create variant-specific output directory
    if variant_id:
        output_dir = f"data/processed/{variant_id}/application_logs"
    else:
        output_dir = "data/processed/application_logs"
    os.makedirs(output_dir, exist_ok=True)
    
    # Check if logs have already been processed for this variant
    processed_files = set()
    if os.path.exists(output_dir):
        for file in os.listdir(output_dir):
            if file.endswith('.jsonl'):
                processed_files.add(file)
    
    # Process Nginx access logs
    if "nginx_access.jsonl" not in processed_files:
        nginx_access_patterns = [
            f"data/logs/{variant_id}/nginx/access.log" if variant_id else None,
            "data/logs/*/nginx/access.log",
            "*/nginx/access.log",
            "nginx/access.log"
        ]
        
        for pattern in nginx_access_patterns:
            if pattern:
                files = glob.glob(pattern)
                for file_path in files:
                    if os.path.exists(file_path):
                        print(f"Processing Nginx access log: {file_path}")
                        output_file = os.path.join(output_dir, "nginx_access.jsonl")
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as fin, \
                             open(output_file, 'w', encoding='utf-8') as fout:
                            for line in fin:
                                line = line.strip()
                                if line:
                                    record = parse_nginx_access_log(line)
                                    if record and variant_id:
                                        record["variant_id"] = variant_id
                                    if record:
                                        fout.write(json.dumps(record, ensure_ascii=False) + '\n')
                        print(f"Converted Nginx access log to {output_file}")
                        break
    else:
        print("Nginx access logs already processed, skipping...")
    
    # Process Nginx error logs
    if "nginx_error.jsonl" not in processed_files:
        nginx_error_patterns = [
            f"data/logs/{variant_id}/nginx/error.log" if variant_id else None,
            "data/logs/*/nginx/error.log",
            "*/nginx/error.log",
            "nginx/error.log"
        ]
        
        for pattern in nginx_error_patterns:
            if pattern:
                files = glob.glob(pattern)
                for file_path in files:
                    if os.path.exists(file_path):
                        print(f"Processing Nginx error log: {file_path}")
                        output_file = os.path.join(output_dir, "nginx_error.jsonl")
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as fin, \
                             open(output_file, 'w', encoding='utf-8') as fout:
                            for line in fin:
                                line = line.strip()
                                if line:
                                    record = parse_nginx_error_log(line)
                                    if record and variant_id:
                                        record["variant_id"] = variant_id
                                    if record:
                                        fout.write(json.dumps(record, ensure_ascii=False) + '\n')
                        print(f"Converted Nginx error log to {output_file}")
                        break
    else:
        print("Nginx error logs already processed, skipping...")
    
    # Process PHP-FPM logs
    if "php_fpm.jsonl" not in processed_files:
        php_fpm_patterns = [
            f"data/logs/{variant_id}/php7.4-fpm.log" if variant_id else None,
            "data/logs/*/php7.4-fpm.log",
            "*/php7.4-fpm.log",
            "php7.4-fpm.log"
        ]
        
        for pattern in php_fpm_patterns:
            if pattern:
                files = glob.glob(pattern)
                for file_path in files:
                    if os.path.exists(file_path):
                        print(f"Processing PHP-FPM log: {file_path}")
                        output_file = os.path.join(output_dir, "php_fpm.jsonl")
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as fin, \
                             open(output_file, 'w', encoding='utf-8') as fout:
                            for line in fin:
                                line = line.strip()
                                if line:
                                    record = parse_php_log(line)
                                    if record and variant_id:
                                        record["variant_id"] = variant_id
                                    if record:
                                        fout.write(json.dumps(record, ensure_ascii=False) + '\n')
                        print(f"Converted PHP-FPM log to {output_file}")
                        break
    else:
        print("PHP-FPM logs already processed, skipping...")
    
    # Process syslog
    if "syslog.jsonl" not in processed_files:
        syslog_patterns = [
            f"data/logs/{variant_id}/syslog" if variant_id else None,
            "data/logs/*/syslog",
            "*/syslog",
            "syslog"
        ]
        
        for pattern in syslog_patterns:
            if pattern:
                files = glob.glob(pattern)
                for file_path in files:
                    if os.path.exists(file_path):
                        print(f"Processing syslog: {file_path}")
                        output_file = os.path.join(output_dir, "syslog.jsonl")
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as fin, \
                             open(output_file, 'w', encoding='utf-8') as fout:
                            for line in fin:
                                line = line.strip()
                                if line:
                                    record = {
                                        "timestamp": None,
                                        "host": HOSTNAME,
                                        "source_type": "syslog",
                                        "event_type": "system_log",
                                        "severity": "info",
                                        "process": "system",
                                        "user": None,
                                        "is_attack": None,
                                        "details": {"raw": line}
                                    }
                                    if variant_id:
                                        record["variant_id"] = variant_id
                                    fout.write(json.dumps(record, ensure_ascii=False) + '\n')
                        print(f"Converted syslog to {output_file}")
                        break
    else:
        print("Syslog already processed, skipping...")
    
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ETL application logs")
    parser.add_argument("--variant-id", help="Variant ID to add to records")
    args = parser.parse_args()
    
    etl_application_logs(args.variant_id) 