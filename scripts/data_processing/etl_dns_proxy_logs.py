#!/usr/bin/env python3
"""
ETL DNS Proxy Logs
Process DNS proxy logs to JSON Lines format
"""

import os
import json
import argparse
from typing import Dict, Any, List
# Fix relative import issue
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from config import get_config

def etl_dns_proxy_logs(variant_id: str = None) -> bool:
    """ETL DNS proxy logs to JSON Lines format"""
    print(f"🚀 Processing DNS proxy logs for variant: {variant_id}")
    
    config = get_config(variant_id)
    # Use absolute paths
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    input_file = os.path.join(base_dir, config.dns_proxy_raw)
    output_file = os.path.join(base_dir, config.dns_proxy_processed)
    
    print(f"📁 Input: {input_file}")
    print(f"📁 Output: {output_file}")
    
    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"Warning: DNS proxy log file not found: {input_file}")
        print("⚠️  No DNS proxy records found")
        return True  # Not an error, just no data
    
    # Create output directory
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # Parse DNS proxy logs
    # The original script had a parse_dns_proxy_log function, but it's not used here.
    # Assuming the intent is to read the raw JSONL file directly.
    records = []
    try:
        with open(input_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    # The original script had a process_dns_proxy_record function,
                    # but it's not used here. Assuming the intent is to just
                    # include the raw data for now.
                    record = {
                        "timestamp": data.get("timestamp", "unknown"),
                        "protocol": "dns",
                        "client_ip": data.get("client_ip", "unknown"),
                        "query_type": data.get("record_type", "A"),
                        "query_domain": data.get("query", ""),
                        "response_ip": data.get("response", ""),
                        "response_time": data.get("response_time", 0),
                        "response_size": data.get("response_size", 0),
                        "attack_detection": {"is_attack": data.get("is_attack", False)},
                        "attack_stage": data.get("attack_stage", ""),  # Add attack_stage field
                        "raw_query": data.get("query", ""),
                        "raw_response": data.get("response", "")
                    }
                    records.append(record)
                except json.JSONDecodeError as e:
                    print(f"Warning: Invalid JSON on line {line_num}: {e}")
                    continue
    except Exception as e:
        print(f"Error reading DNS proxy log: {e}")
    
    if not records:
        print("⚠️  No DNS proxy records found")
        return True  # Not an error, just no data
    
    # Add variant information and variant-specific processing
    for record in records:
        record["variant_id"] = variant_id
        record["source_type"] = "dns_proxy"
        
        # Variant-specific processing based on attack intensity
        if variant_id == "lowscan_stealthy":
            # Stealthy variant: focus on subtle attack patterns
            record["attack_intensity"] = "low"
            record["processing_priority"] = "high"  # High priority for stealth detection
            record["risk_score"] = 0.3 if record["attack_detection"]["is_attack"] else 0.1
        elif variant_id == "lowscan_moderate":
            # Moderate variant: balanced processing
            record["attack_intensity"] = "medium"
            record["processing_priority"] = "medium"
            record["risk_score"] = 0.6 if record["attack_detection"]["is_attack"] else 0.2
        elif variant_id == "lowscan_aggressive":
            # Aggressive variant: focus on high-volume attack patterns
            record["attack_intensity"] = "high"
            record["processing_priority"] = "low"  # Lower priority due to obvious attacks
            record["risk_score"] = 0.9 if record["attack_detection"]["is_attack"] else 0.3
        else:
            # Default processing
            record["attack_intensity"] = "unknown"
            record["processing_priority"] = "medium"
            record["risk_score"] = 0.5 if record["attack_detection"]["is_attack"] else 0.2
    
    # Save processed logs
    try:
        with open(output_file, 'w') as f:
            for record in records:
                f.write(json.dumps(record, ensure_ascii=False) + '\n')
        print(f"✅ Processed {len(records)} DNS proxy records saved to {output_file}")
        return True
    except Exception as e:
        print(f"Error saving processed DNS proxy logs: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Process DNS proxy logs")
    parser.add_argument("--variant-id", required=True, help="Variant ID")
    
    args = parser.parse_args()
    
    success = etl_dns_proxy_logs(args.variant_id)
    return 0 if success else 1

if __name__ == "__main__":
    exit(main()) 