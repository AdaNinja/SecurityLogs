#!/usr/bin/env python3
"""
Variant-Specific Log Merger
Merge all log sources for a specific variant into unified JSON Lines format
"""

import os
import json
import glob
import argparse
from datetime import datetime

def merge_variant_logs(variant_id, input_dir, output_file):
    """Merge all log sources for a specific variant"""
    
    print(f"Merging logs for variant: {variant_id}")
    print(f"Input directory: {input_dir}")
    print(f"Output file: {output_file}")
    
    # Create output directory if needed
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # Collect all log files for this variant
    log_files = []
    
    # Container logs
    container_logs = glob.glob(os.path.join(input_dir, "*_logs.txt"))
    log_files.extend(container_logs)
    
    # Application logs
    app_logs = glob.glob(os.path.join(input_dir, "*.log"))
    log_files.extend(app_logs)
    
    # JSON logs (including subdirectories)
    json_logs = glob.glob(os.path.join(input_dir, "*.json"))
    json_logs.extend(glob.glob(os.path.join(input_dir, "output", "*.json")))
    log_files.extend(json_logs)
    
    # PCAP files (will be converted to JSON)
    pcap_files = glob.glob(os.path.join(input_dir, "*.pcap"))
    
    print(f"Found {len(log_files)} log files and {len(pcap_files)} PCAP files")
    
    # Merge all logs
    total_records = 0
    with open(output_file, 'w', encoding='utf-8') as fout:
        
        # Process text logs
        for log_file in log_files:
            print(f"Processing: {log_file}")
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as fin:
                    for line_num, line in enumerate(fin, 1):
                        line = line.strip()
                        if line:
                            record = parse_log_line(line, log_file, variant_id)
                            if record:
                                fout.write(json.dumps(record, ensure_ascii=False) + '\n')
                                total_records += 1
            except Exception as e:
                print(f"Error processing {log_file}: {e}")
        
        # Process JSON logs
        for json_file in json_logs:
            print(f"Processing JSON: {json_file}")
            try:
                with open(json_file, 'r', encoding='utf-8') as fin:
                    data = json.load(fin)
                    records = parse_json_log(data, json_file, variant_id)
                    for record in records:
                        fout.write(json.dumps(record, ensure_ascii=False) + '\n')
                        total_records += 1
            except Exception as e:
                print(f"Error processing JSON {json_file}: {e}")
        
        # Process PCAP files (simplified - just create metadata records)
        for pcap_file in pcap_files:
            print(f"Processing PCAP: {pcap_file}")
            record = create_pcap_record(pcap_file, variant_id)
            if record:
                fout.write(json.dumps(record, ensure_ascii=False) + '\n')
                total_records += 1
    
    print(f"Successfully merged {total_records} records to {output_file}")
    
    # Generate variant-specific statistics
    generate_variant_stats(output_file, variant_id)

def parse_log_line(line, log_file, variant_id):
    """Parse a single log line and convert to unified format"""
    
    # Determine source type based on filename
    filename = os.path.basename(log_file).lower()
    if "webapp" in filename:
        source_type = "webapp"
        process = "nginx"
    elif "attacker" in filename:
        source_type = "attacker"
        process = "sqlmap"
    elif "tcpdump" in filename:
        source_type = "network"
        process = "tcpdump"
    else:
        source_type = "application"
        process = "unknown"
    
    # Extract timestamp if present
    timestamp = extract_timestamp(line)
    
    # Determine event type and severity
    event_type, severity, is_attack = analyze_log_content(line, source_type)
    
    return {
        "timestamp": timestamp,
        "variant_id": variant_id,
        "host": os.uname().nodename,
        "source_type": source_type,
        "event_type": event_type,
        "severity": severity,
        "process": process,
        "user": None,
        "is_attack": is_attack,
        "attack_stage": determine_attack_stage(line, source_type),
        "details": {"raw": line}
    }

def parse_json_log(data, json_file, variant_id):
    """Parse JSON log files and convert to unified format"""
    
    records = []
    
    # Handle different JSON log formats
    if isinstance(data, dict):
        if "results" in data:  # Attack results format
            for result in data.get("results", []):
                record = {
                    "timestamp": data.get("container_attack_timestamp"),
                    "variant_id": variant_id,
                    "host": os.uname().nodename,
                    "source_type": "attack",
                    "event_type": result.get("type", "attack"),
                    "severity": "error" if result.get("success") else "info",
                    "process": "sqlmap",
                    "user": "attacker",
                    "is_attack": "Exploit",
                    "attack_stage": "exploit",
                    "details": result
                }
                records.append(record)
        else:  # Single record format
            record = {
                "timestamp": data.get("timestamp"),
                "variant_id": variant_id,
                "host": os.uname().nodename,
                "source_type": "application",
                "event_type": "log",
                "severity": "info",
                "process": "unknown",
                "user": None,
                "is_attack": None,
                "attack_stage": None,
                "details": data
            }
            records.append(record)
    
    return records

def create_pcap_record(pcap_file, variant_id):
    """Create a record for PCAP file metadata"""
    
    try:
        stat = os.stat(pcap_file)
        size_mb = stat.st_size / (1024 * 1024)
        
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "variant_id": variant_id,
            "host": os.uname().nodename,
            "source_type": "network",
            "event_type": "pcap_capture",
            "severity": "info",
            "process": "tcpdump",
            "user": None,
            "is_attack": None,
            "attack_stage": None,
            "details": {
                "filename": os.path.basename(pcap_file),
                "size_mb": round(size_mb, 2),
                "note": "PCAP file captured - use Zeek/Suricata for detailed analysis"
            }
        }
    except Exception as e:
        print(f"Error creating PCAP record: {e}")
        return None

def extract_timestamp(line):
    """Extract timestamp from log line"""
    
    # Common timestamp patterns
    patterns = [
        r'\[([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z?)\]',  # ISO format
        r'\[([A-Z][a-z]{2} [0-9]{1,2} [0-9:]{8})\]',  # syslog format
        r'([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8})',   # datetime format
    ]
    
    import re
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            ts_str = match.group(1)
            try:
                if 'T' in ts_str:
                    dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                elif len(ts_str.split()) == 3:
                    year = datetime.utcnow().year
                    dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
                else:
                    dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                
                return dt.isoformat() + "Z"
            except Exception:
                continue
    
    return None

def analyze_log_content(line, source_type):
    """Analyze log content to determine event type, severity, and attack status"""
    
    line_lower = line.lower()
    
    # Determine event type
    event_type = "log"
    if "sql" in line_lower or "injection" in line_lower:
        event_type = "sql_injection"
    elif "scan" in line_lower or "nmap" in line_lower:
        event_type = "network_scan"
    elif "login" in line_lower:
        event_type = "login_attempt"
    elif "error" in line_lower:
        event_type = "error"
    
    # Determine severity
    severity = "info"
    if "error" in line_lower or "failed" in line_lower:
        severity = "error"
    elif "warn" in line_lower or "warning" in line_lower:
        severity = "warn"
    
    # Determine if it's an attack
    is_attack = None
    if any(pattern in line_lower for pattern in ["union", "select", "or 1=1", "admin'", "'--"]):
        is_attack = "Exploit"
    elif "scan" in line_lower and source_type == "attacker":
        is_attack = "Recon"
    
    return event_type, severity, is_attack

def determine_attack_stage(line, source_type):
    """Determine attack stage based on content and source"""
    
    line_lower = line.lower()
    
    if source_type == "attacker":
        if "scan" in line_lower or "recon" in line_lower:
            return "reconnaissance"
        elif "injection" in line_lower or "attack" in line_lower:
            return "exploit"
        elif "dump" in line_lower or "extract" in line_lower:
            return "exfiltration"
    
    return None

def generate_variant_stats(jsonl_file, variant_id):
    """Generate statistics for the variant dataset"""
    
    stats = {
        "variant_id": variant_id,
        "total_records": 0,
        "source_types": {},
        "event_types": {},
        "severity_levels": {},
        "attack_records": 0,
        "normal_records": 0,
        "attack_stages": {}
    }
    
    try:
        with open(jsonl_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        record = json.loads(line)
                        stats["total_records"] += 1
                        
                        # Count source types
                        source_type = record.get("source_type", "unknown")
                        stats["source_types"][source_type] = stats["source_types"].get(source_type, 0) + 1
                        
                        # Count event types
                        event_type = record.get("event_type", "unknown")
                        stats["event_types"][event_type] = stats["event_types"].get(event_type, 0) + 1
                        
                        # Count severity levels
                        severity = record.get("severity", "unknown")
                        stats["severity_levels"][severity] = stats["severity_levels"].get(severity, 0) + 1
                        
                        # Count attack vs normal
                        is_attack = record.get("is_attack")
                        if is_attack:
                            stats["attack_records"] += 1
                        else:
                            stats["normal_records"] += 1
                        
                        # Count attack stages
                        attack_stage = record.get("attack_stage")
                        if attack_stage:
                            stats["attack_stages"][attack_stage] = stats["attack_stages"].get(attack_stage, 0) + 1
                                
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        print(f"Error reading file {jsonl_file}: {e}")
        return
    
    # Save statistics
    stats_file = jsonl_file.replace('.jsonl', '_stats.json')
    with open(stats_file, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)
    
    print(f"Variant statistics saved to {stats_file}")
    print(f"Total records: {stats['total_records']}")
    print(f"Attack records: {stats['attack_records']}")
    print(f"Normal records: {stats['normal_records']}")

def main():
    parser = argparse.ArgumentParser(description='Merge variant-specific logs')
    parser.add_argument('--variant-id', required=True, help='Variant ID')
    parser.add_argument('--input-dir', required=True, help='Input directory')
    parser.add_argument('--output-file', required=True, help='Output file')
    
    args = parser.parse_args()
    
    merge_variant_logs(args.variant_id, args.input_dir, args.output_file)

if __name__ == "__main__":
    main() 