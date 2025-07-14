#!/usr/bin/env python3
"""
Container Logs ETL Script
Convert Docker container logs to unified JSON Lines format
"""

import os
import json
import subprocess
import re
from datetime import datetime

# Container names to process
CONTAINERS = [
    "securitylogs-webapp",
    "securitylogs-attacker", 
    "securitylogs-tcpdump",
    "securitylogs-log-aggregator"
]

HOSTNAME = os.uname().nodename

def parse_container_log_line(line, container_name):
    """Parse container log line and extract structured fields"""
    # Default values
    record = {
        "timestamp": None,
        "host": HOSTNAME,
        "source_type": "container",
        "event_type": None,
        "severity": "info",
        "process": container_name,
        "user": None,
        "is_attack": None,
        "details": {"raw": line}
    }
    
    # Try to extract timestamp from common formats
    ts_patterns = [
        r"\[([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z?)\]",  # ISO format
        r"\[([A-Z][a-z]{2} [0-9]{1,2} [0-9:]{8})\]",  # syslog format
        r"([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8})",   # datetime format
    ]
    
    for pattern in ts_patterns:
        match = re.search(pattern, line)
        if match:
            ts_str = match.group(1)
            try:
                # Handle different timestamp formats
                if 'T' in ts_str:
                    # ISO format
                    dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                elif len(ts_str.split()) == 3:
                    # syslog format
                    year = datetime.utcnow().year
                    dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
                else:
                    # datetime format
                    dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                
                record["timestamp"] = dt.isoformat() + "Z"
                break
            except:
                continue
    
    # Extract event type based on content
    line_lower = line.lower()
    if any(word in line_lower for word in ["error", "failed", "exception"]):
        record["severity"] = "error"
    elif any(word in line_lower for word in ["warn", "warning"]):
        record["severity"] = "warn"
    
    # Determine event type based on container and content
    if container_name == "securitylogs-attacker":
        if "sql" in line_lower or "injection" in line_lower:
            record["event_type"] = "sql_injection"
            record["is_attack"] = "Exploit"
        elif "scan" in line_lower or "nmap" in line_lower:
            record["event_type"] = "network_scan"
            record["is_attack"] = "Recon"
        elif "attack" in line_lower:
            record["event_type"] = "attack"
            record["is_attack"] = "Exploit"
    elif container_name == "securitylogs-webapp":
        if "login" in line_lower:
            record["event_type"] = "login_attempt"
        elif "error" in line_lower:
            record["event_type"] = "error"
    elif container_name == "securitylogs-tcpdump":
        if "capture" in line_lower:
            record["event_type"] = "traffic_capture"
    
    return record

def get_container_logs(container_name):
    """Get logs from Docker container"""
    try:
        result = subprocess.run(
            ["docker", "logs", container_name],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return result.stdout.splitlines()
        else:
            print(f"Failed to get logs from {container_name}")
            return []
    except Exception as e:
        print(f"Error getting logs from {container_name}: {e}")
        return []

def etl_container_logs():
    """ETL all container logs to JSON Lines format"""
    output_dir = "container_logs"
    os.makedirs(output_dir, exist_ok=True)
    
    for container in CONTAINERS:
        print(f"Processing container: {container}")
        logs = get_container_logs(container)
        
        if not logs:
            print(f"No logs found for {container}")
            continue
        
        # Convert to JSON Lines
        output_file = os.path.join(output_dir, f"{container}.jsonl")
        with open(output_file, 'w', encoding='utf-8') as f:
            for line in logs:
                if line.strip():
                    record = parse_container_log_line(line, container)
                    f.write(json.dumps(record, ensure_ascii=False) + '\n')
        
        print(f"Converted {len(logs)} lines to {output_file}")

if __name__ == "__main__":
    etl_container_logs() 