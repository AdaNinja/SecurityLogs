#!/usr/bin/env python3
"""
Unified Log Merger
Merge all ETL'd log sources into a single unified dataset
"""

import os
import json
import glob
from datetime import datetime

def merge_all_logs():
    """Merge all JSON Lines files into a single unified dataset"""
    
    # Define log source directories
    log_dirs = [
        "data/processed/host_logs",
        "data/processed/container_logs", 
        "data/processed/application_logs",
        "data/processed/attack_logs",
        "data/processed/webapp_logs"
    ]
    
    # Output file
    output_file = "data/processed/unified_logs.jsonl"
    
    # Collect all JSONL files
    all_files = []
    for log_dir in log_dirs:
        if os.path.exists(log_dir):
            jsonl_files = glob.glob(os.path.join(log_dir, "*.jsonl"))
            all_files.extend(jsonl_files)
    
    print(f"Found {len(all_files)} JSONL files to merge")
    
    # Merge all logs
    total_records = 0
    with open(output_file, 'w', encoding='utf-8') as fout:
        for jsonl_file in all_files:
            print(f"Processing: {jsonl_file}")
            try:
                with open(jsonl_file, 'r', encoding='utf-8') as fin:
                    for line in fin:
                        line = line.strip()
                        if line:
                            # Parse and validate JSON
                            try:
                                record = json.loads(line)
                                
                                # Ensure required fields exist
                                if not record.get("timestamp"):
                                    # Add current timestamp if missing
                                    record["timestamp"] = datetime.utcnow().isoformat() + "Z"
                                
                                if not record.get("host"):
                                    record["host"] = os.uname().nodename
                                
                                # Write to unified file
                                fout.write(json.dumps(record, ensure_ascii=False) + '\n')
                                total_records += 1
                                
                            except json.JSONDecodeError as e:
                                print(f"Warning: Invalid JSON in {jsonl_file}: {e}")
                                continue
            except Exception as e:
                print(f"Error processing {jsonl_file}: {e}")
    
    print(f"Successfully merged {total_records} records to {output_file}")
    
    # Generate summary statistics
    generate_summary_stats(output_file)

def generate_summary_stats(jsonl_file):
    """Generate summary statistics for the unified dataset"""
    
    stats = {
        "total_records": 0,
        "source_types": {},
        "event_types": {},
        "severity_levels": {},
        "attack_records": 0,
        "normal_records": 0,
        "time_range": {"start": None, "end": None}
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
                        
                        # Track time range
                        timestamp = record.get("timestamp")
                        if timestamp:
                            try:
                                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                                if not stats["time_range"]["start"] or dt < stats["time_range"]["start"]:
                                    stats["time_range"]["start"] = dt
                                if not stats["time_range"]["end"] or dt > stats["time_range"]["end"]:
                                    stats["time_range"]["end"] = dt
                            except Exception:
                                pass
                                
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        print(f"Error processing {jsonl_file}: {e}")
    
    # Save statistics
    stats_file = "data/dataset_statistics.json"
    with open(stats_file, 'w', encoding='utf-8') as f:
        # Convert datetime objects to strings for JSON serialization
        if stats["time_range"]["start"]:
            stats["time_range"]["start"] = stats["time_range"]["start"].isoformat()
        if stats["time_range"]["end"]:
            stats["time_range"]["end"] = stats["time_range"]["end"].isoformat()
        
        json.dump(stats, f, indent=2, ensure_ascii=False)
    
    print(f"Dataset statistics saved to {stats_file}")
    print(f"Total records: {stats['total_records']}")
    print(f"Attack records: {stats['attack_records']}")
    print(f"Normal records: {stats['normal_records']}")
    print(f"Source types: {list(stats['source_types'].keys())}")

if __name__ == "__main__":
    merge_all_logs() 