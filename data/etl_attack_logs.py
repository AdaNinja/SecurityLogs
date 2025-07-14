#!/usr/bin/env python3
"""
Attack Logs ETL Script
Convert attack tool logs and results to unified JSON Lines format
"""

import os
import json
import re
from datetime import datetime

HOSTNAME = os.uname().nodename

def parse_attack_log_json(json_file):
    """Parse attack log JSON files"""
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        records = []
        
        # Extract base metadata
        base_metadata = {
            "timestamp": data.get("container_attack_timestamp"),
            "host": HOSTNAME,
            "source_type": "attack",
            "process": data.get("container_id", "attacker"),
            "user": "attacker",
            "is_attack": "Exploit"
        }
        
        # Process each attack result
        for result in data.get("results", []):
            record = base_metadata.copy()
            record.update({
                "event_type": result.get("type", "attack"),
                "severity": "info",
                "details": {
                    "raw": json.dumps(result, ensure_ascii=False),
                    "payload": result.get("payload"),
                    "status_code": result.get("status_code"),
                    "response_length": result.get("response_length"),
                    "response_time": result.get("response_time"),
                    "success": result.get("success"),
                    "sql_error": result.get("sql_error")
                }
            })
            
            # Determine severity based on success/error
            if result.get("sql_error"):
                record["severity"] = "warn"
            if result.get("success"):
                record["severity"] = "error"  # Successful attack is concerning
            
            records.append(record)
        
        return records
    except Exception as e:
        print(f"Error parsing {json_file}: {e}")
        return []

def parse_sqlmap_log(log_file):
    """Parse SQLMap log files"""
    records = []
    
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Extract timestamp if present
                timestamp = None
                ts_match = re.search(r'\[([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8})\]', line)
                if ts_match:
                    try:
                        dt = datetime.strptime(ts_match.group(1), "%Y-%m-%d %H:%M:%S")
                        timestamp = dt.isoformat() + "Z"
                    except:
                        pass
                
                # Determine event type
                event_type = "sqlmap_log"
                if "injection" in line.lower():
                    event_type = "sql_injection"
                elif "scan" in line.lower():
                    event_type = "vulnerability_scan"
                elif "error" in line.lower():
                    event_type = "error"
                
                # Determine severity
                severity = "info"
                if "error" in line.lower():
                    severity = "error"
                elif "warning" in line.lower():
                    severity = "warn"
                
                record = {
                    "timestamp": timestamp,
                    "host": HOSTNAME,
                    "source_type": "sqlmap",
                    "event_type": event_type,
                    "severity": severity,
                    "process": "sqlmap",
                    "user": "attacker",
                    "is_attack": "Exploit",
                    "details": {"raw": line}
                }
                
                records.append(record)
    
    except Exception as e:
        print(f"Error parsing {log_file}: {e}")
    
    return records

def parse_nmap_log(log_file):
    """Parse Nmap log files"""
    records = []
    
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                # Extract timestamp if present
                timestamp = None
                ts_match = re.search(r'([0-9]{2}:[0-9]{2}:[0-9]{2})', line)
                if ts_match:
                    try:
                        # Use current date with time from log
                        current_date = datetime.now().strftime("%Y-%m-%d")
                        dt = datetime.strptime(f"{current_date} {ts_match.group(1)}", "%Y-%m-%d %H:%M:%S")
                        timestamp = dt.isoformat() + "Z"
                    except:
                        pass
                
                # Determine event type
                event_type = "nmap_scan"
                if "open" in line.lower():
                    event_type = "port_discovery"
                elif "closed" in line.lower():
                    event_type = "port_scan"
                elif "filtered" in line.lower():
                    event_type = "port_filtered"
                
                record = {
                    "timestamp": timestamp,
                    "host": HOSTNAME,
                    "source_type": "nmap",
                    "event_type": event_type,
                    "severity": "info",
                    "process": "nmap",
                    "user": "attacker",
                    "is_attack": "Recon",
                    "details": {"raw": line}
                }
                
                records.append(record)
    
    except Exception as e:
        print(f"Error parsing {log_file}: {e}")
    
    return records

def etl_attack_logs():
    """ETL attack logs to JSON Lines format"""
    output_dir = "attack_logs"
    os.makedirs(output_dir, exist_ok=True)
    
    # Process attack JSON logs - look for any variant directory
    attack_json_files = []
    for variant_dir in os.listdir("data/logs"):
        potential_log = f"data/logs/{variant_dir}/output/container_attack_log.json"
        if os.path.exists(potential_log):
            attack_json_files.append(potential_log)
    
    for json_file in attack_json_files:
        if os.path.exists(json_file):
            print(f"Processing attack log: {json_file}")
            records = parse_attack_log_json(json_file)
            
            if records:
                output_file = os.path.join(output_dir, "attack_results.jsonl")
                with open(output_file, 'w', encoding='utf-8') as f:
                    for record in records:
                        f.write(json.dumps(record, ensure_ascii=False) + '\n')
                print(f"Converted {len(records)} attack records to {output_file}")
        else:
            print(f"Attack log not found: {json_file}")
    
    # Process SQLMap logs (if they exist) - look for any variant directory
    sqlmap_logs = []
    for variant_dir in os.listdir("data/logs"):
        potential_logs = [
            f"data/logs/{variant_dir}/logs/sqlmap.log",
            f"data/logs/{variant_dir}/output/sqlmap_*.log"
        ]
        for log_pattern in potential_logs:
            if os.path.exists(log_pattern):
                sqlmap_logs.append(log_pattern)
    
    for log_pattern in sqlmap_logs:
        if os.path.exists(log_pattern):
            print(f"Processing SQLMap log: {log_pattern}")
            records = parse_sqlmap_log(log_pattern)
            
            if records:
                output_file = os.path.join(output_dir, "sqlmap_logs.jsonl")
                with open(output_file, 'w', encoding='utf-8') as f:
                    for record in records:
                        f.write(json.dumps(record, ensure_ascii=False) + '\n')
                print(f"Converted {len(records)} SQLMap records to {output_file}")
        else:
            print(f"SQLMap log not found: {log_pattern}")
    
    # Process Nmap logs (if they exist) - look for any variant directory
    nmap_logs = []
    for variant_dir in os.listdir("data/logs"):
        potential_logs = [
            f"data/logs/{variant_dir}/logs/nmap.log",
            f"data/logs/{variant_dir}/output/nmap_*.log"
        ]
        for log_pattern in potential_logs:
            if os.path.exists(log_pattern):
                nmap_logs.append(log_pattern)
    
    for log_pattern in nmap_logs:
        if os.path.exists(log_pattern):
            print(f"Processing Nmap log: {log_pattern}")
            records = parse_nmap_log(log_pattern)
            
            if records:
                output_file = os.path.join(output_dir, "nmap_logs.jsonl")
                with open(output_file, 'w', encoding='utf-8') as f:
                    for record in records:
                        f.write(json.dumps(record, ensure_ascii=False) + '\n')
                print(f"Converted {len(records)} Nmap records to {output_file}")
        else:
            print(f"Nmap log not found: {log_pattern}")

if __name__ == "__main__":
    etl_attack_logs() 