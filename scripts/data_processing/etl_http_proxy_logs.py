#!/usr/bin/env python3
"""
ETL HTTP Proxy Logs
Process HTTP proxy logs to JSON Lines format
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
from datetime import datetime

def parse_http_proxy_log(line: str) -> Dict[str, Any]:
    """Parse HTTP proxy log line"""
    try:
        # Basic HTTP proxy log format: timestamp method url status size
        parts = line.strip().split()
        if len(parts) < 4:
            return None
        
        timestamp_str = parts[0]
        method = parts[1]
        url = parts[2]
        status = parts[3]
        size = parts[4] if len(parts) > 4 else "0"
        
        # Parse timestamp
        try:
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            timestamp = dt.isoformat() + 'Z'
        except:
            timestamp = timestamp_str
        
        # Determine event type and severity
        event_type = "http_proxy_request"
        severity = "info"
        
        if status.startswith('4'):
            event_type = "http_proxy_error_4xx"
            severity = "warn"
        elif status.startswith('5'):
            event_type = "http_proxy_error_5xx"
            severity = "error"
        
        # Check for attack patterns
        is_attack = False
        attack_stage = None
        
        if any(pattern in url.lower() for pattern in ['union', 'select', 'or 1=1', 'admin\'', '\'--']):
            is_attack = True
            attack_stage = "exploit"
            event_type = "sql_injection_attempt"
        
        record = {
            "timestamp": timestamp,
            "host": os.uname().nodename,
            "source_type": "http_proxy",
            "event_type": event_type,
            "severity": severity,
            "process": "http_proxy",
            "user": None,
            "is_attack": is_attack,
            "attack_stage": attack_stage,
            "details": {
                "raw": line,
                "method": method,
                "url": url,
                "status": status,
                "size": size
            }
        }
        
        return record
        
    except Exception as e:
        print(f"Error parsing HTTP proxy log line: {e}")
        return None

def etl_http_proxy_logs(variant_id: str = None) -> bool:
    """ETL HTTP proxy logs to JSON Lines format"""
    print(f"🚀 Processing HTTP proxy logs for variant: {variant_id}")
    
    config = get_config(variant_id)
    # Use absolute paths
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    input_file = os.path.join(base_dir, config.http_proxy_raw)
    output_file = os.path.join(base_dir, config.http_proxy_processed)
    
    print(f"📁 Input: {input_file}")
    print(f"📁 Output: {output_file}")
    
    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"Warning: HTTP proxy log file not found: {input_file}")
        print("⚠️  No HTTP proxy records found")
        return True  # Not an error, just no data
    
    # Create output directory
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # Process the log file
    processed_count = 0
    error_count = 0
    
    try:
        with open(input_file, 'r', encoding='utf-8') as infile, \
             open(output_file, 'w', encoding='utf-8') as outfile:
            
            for line_num, line in enumerate(infile, 1):
                try:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Parse the log line
                    record = parse_http_proxy_log(line)
                    
                    if record:
                        # Add variant_id and variant-specific processing
                        if variant_id:
                            record["variant_id"] = variant_id
                            
                            # Variant-specific processing based on attack intensity
                            if variant_id == "lowscan_stealthy":
                                # Stealthy variant: focus on subtle HTTP attack patterns
                                record["attack_intensity"] = "low"
                                record["processing_priority"] = "high"  # High priority for stealth detection
                                record["risk_score"] = 0.4 if record.get("is_attack", False) else 0.1
                                # Enhanced detection for stealthy patterns
                                if any(pattern in record.get("details", {}).get("url", "").lower() 
                                       for pattern in ['union', 'select', 'or 1=1', 'admin\'', '\'--']):
                                    record["stealth_detection"] = True
                                    record["risk_score"] = 0.6
                            elif variant_id == "lowscan_moderate":
                                # Moderate variant: balanced HTTP processing
                                record["attack_intensity"] = "medium"
                                record["processing_priority"] = "medium"
                                record["risk_score"] = 0.7 if record.get("is_attack", False) else 0.2
                            elif variant_id == "lowscan_aggressive":
                                # Aggressive variant: focus on high-volume HTTP attack patterns
                                record["attack_intensity"] = "high"
                                record["processing_priority"] = "low"  # Lower priority due to obvious attacks
                                record["risk_score"] = 0.9 if record.get("is_attack", False) else 0.3
                                # Enhanced detection for aggressive patterns
                                if record.get("is_attack", False):
                                    record["aggressive_detection"] = True
                            else:
                                # Default processing
                                record["attack_intensity"] = "unknown"
                                record["processing_priority"] = "medium"
                                record["risk_score"] = 0.5 if record.get("is_attack", False) else 0.2
                        
                        # Write to output file
                        outfile.write(json.dumps(record, ensure_ascii=False) + '\n')
                        processed_count += 1
                    else:
                        error_count += 1
                        
                except Exception as e:
                    error_count += 1
                    if error_count <= 5:  # Show first 5 errors
                        print(f"Error processing line {line_num}: {e}")
        
        print(f"✅ HTTP proxy logs processing completed!")
        print(f"📊 Processed: {processed_count} records")
        print(f"❌ Errors: {error_count} records")
        print(f"📄 Output file: {output_file}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error processing HTTP proxy logs: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="ETL HTTP proxy logs")
    parser.add_argument("--variant-id", required=True, help="Variant ID")
    
    args = parser.parse_args()
    
    success = etl_http_proxy_logs(args.variant_id)
    return 0 if success else 1

if __name__ == "__main__":
    exit(main()) 