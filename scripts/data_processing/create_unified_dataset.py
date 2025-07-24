#!/usr/bin/env python3
"""
Create Unified Dataset
Combine all log data into a single CSV file for easy analysis
"""

import os
import json
import csv
import argparse
import glob
from datetime import datetime
from typing import Dict, List, Any
import sys

def load_jsonl_file(file_path: str) -> List[Dict[str, Any]]:
    """Load data from a JSONL file"""
    data = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    record = json.loads(line)
                    data.append(record)
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
    return data

def flatten_dict(d: Dict[str, Any], parent_key: str = '', sep: str = '_') -> Dict[str, Any]:
    """Flatten nested dictionary"""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

def create_unified_dataset(variant_id: str) -> bool:
    """Create unified CSV dataset from all log files"""
    try:
        print(f"Creating unified dataset for variant: {variant_id}")
        
        # Define data sources with absolute paths
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        data_sources = {
            'system_logs': os.path.join(base_dir, f"data/processed/{variant_id}/system_logs/*.jsonl"),
            'security_data': os.path.join(base_dir, f"data/processed/{variant_id}/security_data/*.jsonl"),
            'dns_data': os.path.join(base_dir, f"data/processed/{variant_id}/dns_data/*.jsonl"),
            'proxy_data': os.path.join(base_dir, f"data/processed/{variant_id}/proxy_data/*.jsonl"),
            'analysis': os.path.join(base_dir, f"data/processed/{variant_id}/analysis/*.jsonl")
        }
        
        all_data = []
        source_counts = {}
        
        # Load data from each source
        for source_name, pattern in data_sources.items():
            print(f"Processing {source_name}...")
            source_data = []
            
            # Find all matching files
            files = glob.glob(pattern)
            for file_path in files:
                data = load_jsonl_file(file_path)
                # Add source information and variant-specific processing
                for record in data:
                    record['data_source'] = source_name
                    record['source_file'] = os.path.basename(file_path)
                    
                    # Variant-specific dataset processing
                    if variant_id == "lowscan_stealthy":
                        # Stealthy variant: enhance subtle attack detection
                        record['variant_processing'] = 'stealth_enhanced'
                        if record.get('is_attack', False):
                            record['stealth_detection_priority'] = 'high'
                            record['analysis_focus'] = 'subtle_patterns'
                    elif variant_id == "lowscan_moderate":
                        # Moderate variant: balanced analysis
                        record['variant_processing'] = 'moderate_balanced'
                        record['analysis_focus'] = 'balanced_patterns'
                    elif variant_id == "lowscan_aggressive":
                        # Aggressive variant: focus on high-volume patterns
                        record['variant_processing'] = 'aggressive_volume'
                        if record.get('is_attack', False):
                            record['volume_analysis_priority'] = 'high'
                            record['analysis_focus'] = 'high_volume_patterns'
                    else:
                        record['variant_processing'] = 'default'
                        record['analysis_focus'] = 'general_patterns'
                source_data.extend(data)
            
            source_counts[source_name] = len(source_data)
            all_data.extend(source_data)
            print(f"  Loaded {len(source_data)} records from {len(files)} files")
        
        if not all_data:
            print("No data found!")
            return False
        
        # Flatten all records and collect all possible fields
        flattened_data = []
        all_fields = set()
        
        for record in all_data:
            flattened = flatten_dict(record)
            flattened_data.append(flattened)
            all_fields.update(flattened.keys())
        
        # Sort fields for consistent output
        field_order = [
            'timestamp', 'variant_id', 'data_source', 'source_file',
            'host', 'source_type', 'event_type', 'severity', 'process',
            'user', 'is_attack', 'attack_stage'
        ]
        
        # Add remaining fields in alphabetical order
        remaining_fields = sorted([f for f in all_fields if f not in field_order])
        all_fields_ordered = field_order + remaining_fields
        
        # Create output directory with absolute path
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        output_dir = os.path.join(base_dir, f"data/processed/{variant_id}/datasets")
        os.makedirs(output_dir, exist_ok=True)
        
        # Write CSV file
        csv_file = os.path.join(output_dir, "unified_dataset.csv")
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=all_fields_ordered)
            writer.writeheader()
            
            for record in flattened_data:
                # Ensure all fields are present (fill missing with empty string)
                row = {field: record.get(field, '') for field in all_fields_ordered}
                writer.writerow(row)
        
        # Create summary
        summary_file = os.path.join(output_dir, "dataset_summary.txt")
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(f"Unified Dataset Summary for {variant_id}\n")
            f.write("=" * 50 + "\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"Total records: {len(flattened_data)}\n")
            f.write(f"Total fields: {len(all_fields_ordered)}\n\n")
            
            f.write("Data Source Breakdown:\n")
            f.write("-" * 30 + "\n")
            for source, count in source_counts.items():
                f.write(f"{source}: {count} records\n")
            
            f.write(f"\nOutput files:\n")
            f.write(f"- CSV dataset: {csv_file}\n")
            f.write(f"- Summary: {summary_file}\n")
        
        print(f"\n✅ Unified dataset created successfully!")
        print(f"📊 Total records: {len(flattened_data)}")
        print(f"📋 Total fields: {len(all_fields_ordered)}")
        print(f"📁 Output directory: {output_dir}")
        print(f"📄 CSV file: {csv_file}")
        print(f"📝 Summary file: {summary_file}")
        
        # Print field summary
        print(f"\n📋 Field breakdown:")
        for source, count in source_counts.items():
            print(f"  {source}: {count} records")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating unified dataset: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Create unified CSV dataset from all log files")
    parser.add_argument("--variant-id", required=True, help="Variant ID to process")
    
    args = parser.parse_args()
    create_unified_dataset(args.variant_id)

if __name__ == "__main__":
    main() 