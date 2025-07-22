#!/usr/bin/env python3
"""
Attack Logs ETL Script
Convert attack tool logs and results to unified JSON Lines format
"""

import os
import json
import re
import argparse
import glob
from datetime import datetime
import sys

# 添加MITRE映射器
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from mitre_mapper import MITREMapper

HOSTNAME = os.uname().nodename

# 初始化MITRE映射器
mitre_mapper = MITREMapper()

def parse_attack_log_json(json_file, variant_id=None):
    """Parse attack log JSON files with enhanced fields"""
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
            "is_attack": "Exploit",
            "attack_stage": "exploit"
        }
        
        # Add variant_id if provided
        if variant_id:
            base_metadata["variant_id"] = variant_id
        
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
            
            # Determine attack stage based on event type
            if "recon" in result.get("type", "").lower():
                record["attack_stage"] = "reconnaissance"
            elif "injection" in result.get("type", "").lower():
                record["attack_stage"] = "exploit"
            elif "exfiltration" in result.get("type", "").lower():
                record["attack_stage"] = "exfiltration"
            else:
                record["attack_stage"] = "exploit"
            
            # Determine severity based on success/error
            if result.get("sql_error"):
                record["severity"] = "warn"
            if result.get("success"):
                record["severity"] = "error"  # Successful attack is concerning
            
            # Set is_attack to True for all attack records
            record["is_attack"] = True
            
            # Add MITRE ATT&CK mapping
            mitre_mapping = mitre_mapper.map_attack_pattern(
                record["event_type"], 
                record["details"],
                record["source_type"]
            )
            if mitre_mapping:
                record["mitre_attack"] = mitre_mapping
            
            records.append(record)
        
        return records
    except Exception as e:
        print(f"Error parsing {json_file}: {e}")
        return []

def parse_sqlmap_log(log_file, variant_id=None):
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
                
                details = {"raw": line}
                
                record = {
                    "timestamp": timestamp,
                    "host": HOSTNAME,
                    "source_type": "sqlmap",
                    "event_type": event_type,
                    "severity": severity,
                    "process": "sqlmap",
                    "user": "attacker",
                    "is_attack": True,  # SQLMap logs are always attacks
                    "attack_stage": "exploit",
                    "details": details
                }
                
                # Add variant_id if provided
                if variant_id:
                    record["variant_id"] = variant_id
                
                # Add MITRE ATT&CK mapping
                mitre_mapping = mitre_mapper.map_attack_pattern(
                    event_type, 
                    details,
                    "sqlmap"
                )
                if mitre_mapping:
                    record["mitre_attack"] = mitre_mapping
                
                records.append(record)
    
    except Exception as e:
        print(f"Error parsing {log_file}: {e}")
    
    return records

def parse_nmap_log(log_file, variant_id=None):
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
                
                details = {"raw": line}
                
                record = {
                    "timestamp": timestamp,
                    "host": HOSTNAME,
                    "source_type": "nmap",
                    "event_type": event_type,
                    "severity": "info",
                    "process": "nmap",
                    "user": "attacker",
                    "is_attack": True,  # Nmap logs are always reconnaissance attacks
                    "attack_stage": "reconnaissance",
                    "details": details
                }
                
                # Add variant_id if provided
                if variant_id:
                    record["variant_id"] = variant_id
                
                # Add MITRE ATT&CK mapping
                mitre_mapping = mitre_mapper.map_attack_pattern(
                    event_type, 
                    details,
                    "nmap"
                )
                if mitre_mapping:
                    record["mitre_attack"] = mitre_mapping
                
                records.append(record)
    
    except Exception as e:
        print(f"Error parsing {log_file}: {e}")
    
    return records

def etl_attack_logs(variant_id=None):
    """ETL attack logs to JSON Lines format"""
    # Create variant-specific output directory
    if variant_id:
        output_dir = f"data/processed/{variant_id}/attack_logs"
    else:
        output_dir = "data/processed/attack_logs"
    os.makedirs(output_dir, exist_ok=True)
    
    # Look for attack logs in various possible locations
    attack_logs_found = False
    
    # Check variant-specific attack logs first
    if variant_id:
        attack_log_patterns = [
            f"data/logs/{variant_id}/output/container_attack_log.json",
            f"data/logs/{variant_id}/output/*.json",
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
                                # Single record
                                if variant_id and "variant_id" not in data:
                                    data["variant_id"] = variant_id
                                fout.write(json.dumps(data, ensure_ascii=False) + '\n')
                        
                        print(f"Converted {file_path} to {output_file}")
                        attack_logs_found = True
                        
                    except json.JSONDecodeError as e:
                        print(f"Error parsing JSON from {file_path}: {e}")
                    except Exception as e:
                        print(f"Error processing {file_path}: {e}")
    
    # Fallback: Check other locations
    if not attack_logs_found:
        fallback_patterns = [
            "data/logs/*/output/container_attack_log.json",
            "data/logs/*/output/*.json",
            "data/raw/*/output/*.json",
            "*/output/*.json",
            "*.json"
        ]
        
        for pattern in fallback_patterns:
            files = glob.glob(pattern)
            for file_path in files:
                if os.path.exists(file_path) and "attack" in file_path.lower():
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
                                # Single record
                                if variant_id and "variant_id" not in data:
                                    data["variant_id"] = variant_id
                                fout.write(json.dumps(data, ensure_ascii=False) + '\n')
                        
                        print(f"Converted {file_path} to {output_file}")
                        attack_logs_found = True
                        break
                        
                    except json.JSONDecodeError as e:
                        print(f"Error parsing JSON from {file_path}: {e}")
                    except Exception as e:
                        print(f"Error processing {file_path}: {e}")
    
    if not attack_logs_found:
        print("⚠️  No attack logs found in expected locations")
        return False
    
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ETL attack logs")
    parser.add_argument("--variant-id", help="Variant ID to add to records")
    args = parser.parse_args()
    
    etl_attack_logs(args.variant_id) 