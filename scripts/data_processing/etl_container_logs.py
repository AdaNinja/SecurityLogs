#!/usr/bin/env python3
"""
Container Logs ETL Script
Convert Docker container logs to unified JSON Lines format
"""

import os
import json
import subprocess
import re
import argparse
from datetime import datetime

# Container names to process
CONTAINERS = [
    "securitylogs-webapp",
    "securitylogs-attacker", 
    "securitylogs-tcpdump",
    "securitylogs-log-aggregator"
]

HOSTNAME = os.uname().nodename

def parse_container_log_line(line, container_name, variant_id=None):
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
        "is_attack": False,  # 容器日志默认为非攻击
        "attack_stage": None,
        "details": {"raw": line}
    }
    
    # Add variant_id if provided
    if variant_id:
        record["variant_id"] = variant_id
    
    # Try to extract timestamp from common formats
    ts_patterns = [
        r"\[([A-Z][a-z]{2} [A-Z][a-z]{2} [0-9]{1,2} [0-9:]{8} [A-Z]{3} [0-9]{4})\]",  # Docker format
        r"\[([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z?)\]",  # ISO format
        r"\[([A-Z][a-z]{2} [0-9]{1,2} [0-9:]{8})\]",  # syslog format
        r"([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8})",   # datetime format
    ]
    
    timestamp_found = False
    for pattern in ts_patterns:
        match = re.search(pattern, line)
        if match:
            ts_str = match.group(1)
            try:
                # Handle different timestamp formats
                if len(ts_str.split()) == 6:
                    # Docker format: "Mon Jul 21 10:46:30 UTC 2025"
                    dt = datetime.strptime(ts_str, "%a %b %d %H:%M:%S %Z %Y")
                elif 'T' in ts_str and '-' in ts_str:
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
                timestamp_found = True
                break
            except Exception as e:
                print(f"Warning: Failed to parse timestamp '{ts_str}': {e}")
                continue
    
    # If no timestamp found, use current time as fallback
    if not timestamp_found:
        record["timestamp"] = datetime.utcnow().isoformat() + "Z"
        # Add note to details about missing timestamp
        record["details"]["timestamp_note"] = "Default timestamp applied - original log had no timestamp"
    
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
            record["is_attack"] = True
            record["attack_stage"] = "exploit"
        elif "scan" in line_lower or "nmap" in line_lower:
            record["event_type"] = "network_scan"
            record["is_attack"] = True
            record["attack_stage"] = "reconnaissance"
        elif "attack" in line_lower:
            record["event_type"] = "attack"
            record["is_attack"] = True
            record["attack_stage"] = "exploit"
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

def etl_container_logs(variant_id=None):
    """ETL container logs to JSON Lines format"""
    # Create variant-specific output directory
    if variant_id:
        output_dir = f"data/processed/{variant_id}/container_logs"
    else:
        output_dir = "data/processed/container_logs"
    os.makedirs(output_dir, exist_ok=True)
    
    # Get container logs using docker logs command
    containers = ["securitylogs-webapp", "securitylogs-attacker", "securitylogs-tcpdump", "securitylogs-log-aggregator"]
    
    for container in containers:
        print(f"Processing container: {container}")
        
        try:
            # Get container logs
            result = subprocess.run(
                ["docker", "logs", container],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout.strip():
                # Parse and convert logs
                output_file = os.path.join(output_dir, f"{container}.jsonl")
                with open(output_file, 'w', encoding='utf-8') as fout:
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            record = parse_container_log_line(line, container)
                            if record and variant_id:
                                record["variant_id"] = variant_id
                            if record:
                                fout.write(json.dumps(record, ensure_ascii=False) + '\n')
                
                print(f"Converted {len(result.stdout.strip().split(chr(10)))} lines to {output_file}")
            else:
                print(f"No logs found for {container}")
                
        except subprocess.TimeoutExpired:
            print(f"Timeout getting logs for {container}")
        except Exception as e:
            print(f"Error processing {container}: {e}")
    
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ETL container logs")
    parser.add_argument("--variant-id", help="Variant ID to add to records")
    args = parser.parse_args()
    
    etl_container_logs(args.variant_id) 