#!/usr/bin/env python3
"""
Application Logs ETL Script
Convert Nginx, PHP, and other application logs to unified JSON Lines format
"""

import os
import json
import re
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
    
    return {
        "timestamp": timestamp,
        "host": HOSTNAME,
        "source_type": "nginx_access",
        "event_type": event_type,
        "severity": severity,
        "process": "nginx",
        "user": None,
        "is_attack": is_attack,
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
    
    return {
        "timestamp": timestamp,
        "host": HOSTNAME,
        "source_type": "nginx_error",
        "event_type": "error",
        "severity": severity,
        "process": "nginx",
        "user": None,
        "is_attack": None,
        "details": {
            "raw": line,
            "level": level,
            "pid": pid,
            "message": message
        }
    }

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
            
            return {
                "timestamp": timestamp,
                "host": HOSTNAME,
                "source_type": "php_fpm",
                "event_type": "php_error",
                "severity": severity,
                "process": "php-fpm",
                "user": None,
                "is_attack": None,
                "details": {
                    "raw": line,
                    "level": level,
                    "message": message
                }
            }
    
    # Fallback for unparseable lines
    return {
        "timestamp": None,
        "host": HOSTNAME,
        "source_type": "php_fpm",
        "event_type": "php_log",
        "severity": "info",
        "process": "php-fpm",
        "user": None,
        "is_attack": None,
        "details": {"raw": line}
    }

def etl_application_logs():
    """ETL application logs to JSON Lines format"""
    output_dir = "application_logs"
    os.makedirs(output_dir, exist_ok=True)
    
    # Process Nginx access logs - look for any variant directory
    nginx_access_log = None
    for variant_dir in os.listdir("data/logs"):
        potential_log = f"data/logs/{variant_dir}/nginx/access.log"
        if os.path.exists(potential_log):
            nginx_access_log = potential_log
            break
    
    if nginx_access_log and os.path.exists(nginx_access_log):
        print(f"Processing Nginx access log: {nginx_access_log}")
        output_file = os.path.join(output_dir, "nginx_access.jsonl")
        with open(nginx_access_log, 'r', encoding='utf-8', errors='ignore') as fin, \
             open(output_file, 'w', encoding='utf-8') as fout:
            for line in fin:
                line = line.strip()
                if line:
                    record = parse_nginx_access_log(line)
                    if record:
                        fout.write(json.dumps(record, ensure_ascii=False) + '\n')
        print(f"Converted Nginx access log to {output_file}")
    else:
        print(f"Nginx access log not found: {nginx_access_log}")
    
    # Process Nginx error logs - look for any variant directory
    nginx_error_log = None
    for variant_dir in os.listdir("data/logs"):
        potential_log = f"data/logs/{variant_dir}/nginx/error.log"
        if os.path.exists(potential_log):
            nginx_error_log = potential_log
            break
    
    if nginx_error_log and os.path.exists(nginx_error_log):
        print(f"Processing Nginx error log: {nginx_error_log}")
        output_file = os.path.join(output_dir, "nginx_error.jsonl")
        with open(nginx_error_log, 'r', encoding='utf-8', errors='ignore') as fin, \
             open(output_file, 'w', encoding='utf-8') as fout:
            for line in fin:
                line = line.strip()
                if line:
                    record = parse_nginx_error_log(line)
                    if record:
                        fout.write(json.dumps(record, ensure_ascii=False) + '\n')
        print(f"Converted Nginx error log to {output_file}")
    else:
        print(f"Nginx error log not found")
    
    # Process PHP-FPM logs - look for any variant directory
    php_log = None
    for variant_dir in os.listdir("data/logs"):
        potential_log = f"data/logs/{variant_dir}/php7.4-fpm.log"
        if os.path.exists(potential_log):
            php_log = potential_log
            break
    
    if php_log and os.path.exists(php_log):
        print(f"Processing PHP-FPM log: {php_log}")
        output_file = os.path.join(output_dir, "php_fpm.jsonl")
        with open(php_log, 'r', encoding='utf-8', errors='ignore') as fin, \
             open(output_file, 'w', encoding='utf-8') as fout:
            for line in fin:
                line = line.strip()
                if line:
                    record = parse_php_log(line)
                    if record:
                        fout.write(json.dumps(record, ensure_ascii=False) + '\n')
        print(f"Converted PHP-FPM log to {output_file}")
    else:
        print(f"PHP-FPM log not found")
    
    # Process system logs - look for any variant directory
    syslog_file = None
    for variant_dir in os.listdir("data/logs"):
        potential_log = f"data/logs/{variant_dir}/syslog"
        if os.path.exists(potential_log):
            syslog_file = potential_log
            break
    
    if syslog_file and os.path.exists(syslog_file):
        print(f"Processing system log: {syslog_file}")
        output_file = os.path.join(output_dir, "syslog.jsonl")
        with open(syslog_file, 'r', encoding='utf-8', errors='ignore') as fin, \
             open(output_file, 'w', encoding='utf-8') as fout:
            for line in fin:
                line = line.strip()
                if line:
                    # Simple syslog parsing
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
                    fout.write(json.dumps(record, ensure_ascii=False) + '\n')
        print(f"Converted system log to {output_file}")
    else:
        print(f"System log not found")

if __name__ == "__main__":
    etl_application_logs() 