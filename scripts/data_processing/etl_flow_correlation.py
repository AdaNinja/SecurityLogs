#!/usr/bin/env python3
"""
Flow Correlation ETL Script
Correlate DNS and HTTP flows to identify attack patterns
"""

import os
import json
import argparse
from datetime import datetime, timedelta
from typing import Dict, Any, List

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

def correlate_flows(dns_logs: List[Dict[str, Any]], http_logs: List[Dict[str, Any]], 
                   pcap_logs: List[Dict[str, Any]], variant_id: str) -> List[Dict[str, Any]]:
    """Correlate flows from different sources"""
    print(f"🔄 Correlating flows for variant: {variant_id}")
    
    correlated_flows = []
    
    # Create time-based correlation windows
    correlation_window = timedelta(seconds=30)  # 30-second window
    
    # Group logs by time windows
    dns_by_time = {}
    http_by_time = {}
    pcap_by_time = {}
    
    # Group DNS logs by time
    for dns_record in dns_logs:
        timestamp = dns_record.get('timestamp', '')
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                time_key = dt.replace(second=dt.second - (dt.second % 30), microsecond=0)
                if time_key not in dns_by_time:
                    dns_by_time[time_key] = []
                dns_by_time[time_key].append(dns_record)
            except:
                pass
    
    # Group HTTP logs by time
    for http_record in http_logs:
        timestamp = http_record.get('timestamp', '')
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                time_key = dt.replace(second=dt.second - (dt.second % 30), microsecond=0)
                if time_key not in http_by_time:
                    http_by_time[time_key] = []
                http_by_time[time_key].append(http_record)
            except:
                pass
    
    # Group PCAP logs by time
    for pcap_record in pcap_logs:
        timestamp = pcap_record.get('timestamp', '')
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                time_key = dt.replace(second=dt.second - (dt.second % 30), microsecond=0)
                if time_key not in pcap_by_time:
                    pcap_by_time[time_key] = []
                pcap_by_time[time_key].append(pcap_record)
            except:
                pass
    
    # Correlate flows by time windows
    all_time_keys = set(dns_by_time.keys()) | set(http_by_time.keys()) | set(pcap_by_time.keys())
    
    for time_key in sorted(all_time_keys):
        dns_records = dns_by_time.get(time_key, [])
        http_records = http_by_time.get(time_key, [])
        pcap_records = pcap_by_time.get(time_key, [])
        
        # Create correlation record
        correlation_record = {
            "timestamp": time_key.isoformat() + "Z",
            "variant_id": variant_id,
            "source_type": "flow_correlation",
            "event_type": "flow_correlation",
            "severity": "info",
            "host": os.uname().nodename,
            "correlation_window": "30s",
            "dns_flows": len(dns_records),
            "http_flows": len(http_records),
            "pcap_flows": len(pcap_records),
            "total_flows": len(dns_records) + len(http_records) + len(pcap_records),
            "is_attack": False,
            "attack_stage": None,
            "correlation_details": {
                "dns_queries": [r.get('details', {}).get('query', '') for r in dns_records if r.get('details', {}).get('query')],
                "http_requests": [r.get('details', {}).get('url', '') for r in http_records if r.get('details', {}).get('url')],
                "network_flows": [r.get('src_ip', '') + '->' + r.get('dst_ip', '') for r in pcap_records if r.get('src_ip') and r.get('dst_ip')]
            }
        }
        
        # Determine if this is attack traffic
        attack_indicators = []
        
        # Check DNS attack indicators
        for dns_record in dns_records:
            if dns_record.get('is_attack'):
                attack_indicators.append('dns_attack')
        
        # Check HTTP attack indicators
        for http_record in http_records:
            if http_record.get('is_attack'):
                attack_indicators.append('http_attack')
        
        # Check PCAP attack indicators
        for pcap_record in pcap_records:
            if pcap_record.get('is_attack'):
                attack_indicators.append('network_attack')
        
        if attack_indicators:
            correlation_record["is_attack"] = True
            correlation_record["attack_stage"] = "multi_stage_attack"
            correlation_record["attack_indicators"] = attack_indicators
            correlation_record["severity"] = "high"
        
        correlated_flows.append(correlation_record)
    
    print(f"📊 Correlated {len(correlated_flows)} flow windows")
    print(f"🎯 Found {len([f for f in correlated_flows if f.get('is_attack')])} attack windows")
    
    return correlated_flows

def etl_flow_correlation(variant_id: str = None) -> bool:
    """ETL flow correlation data"""
    print(f"🚀 Processing flow correlation for variant: {variant_id}")
    
    # Input files
    dns_file = f"data/processed/{variant_id}/dns_data/*.jsonl"
    http_file = f"data/processed/{variant_id}/proxy_data/*.jsonl"
    pcap_file = f"data/processed/{variant_id}/security_data/*.jsonl"
    
    # Output file
    output_file = f"data/processed/{variant_id}/analysis/flow_correlation.jsonl"
    
    print(f"📁 DNS logs: {dns_file}")
    print(f"📁 HTTP logs: {http_file}")
    print(f"📁 PCAP logs: {pcap_file}")
    print(f"📁 Output: {output_file}")
    
    # Ensure all necessary directories exist
    os.makedirs(f"data/processed/{variant_id}/dns_data", exist_ok=True)
    os.makedirs(f"data/processed/{variant_id}/proxy_data", exist_ok=True)
    os.makedirs(f"data/processed/{variant_id}/security_data", exist_ok=True)
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # Load DNS logs
    dns_logs = []
    import glob
    for file_path in glob.glob(dns_file):
        data = load_jsonl_file(file_path)
        dns_logs.extend(data)
    print(f"📊 Loaded {len(dns_logs)} DNS records")
    
    # Load HTTP proxy logs
    http_logs = []
    if os.path.exists(http_file):
        http_logs = load_jsonl_file(http_file)
    print(f"📊 Loaded {len(http_logs)} HTTP records")
    
    # Load PCAP logs
    pcap_logs = []
    for file_path in glob.glob(pcap_file):
        data = load_jsonl_file(file_path)
        pcap_logs.extend(data)
    print(f"📊 Loaded {len(pcap_logs)} PCAP records")
    
    # Correlate flows
    correlated_flows = correlate_flows(dns_logs, http_logs, pcap_logs, variant_id)
    
    # Write correlated flows
    with open(output_file, 'w', encoding='utf-8') as f:
        for flow in correlated_flows:
            f.write(json.dumps(flow, ensure_ascii=False) + '\n')
    
    print(f"✅ Flow correlation completed!")
    print(f"📄 Output file: {output_file}")
    print(f"📊 Total correlated flows: {len(correlated_flows)}")
    
    return True

def main():
    parser = argparse.ArgumentParser(description="ETL flow correlation")
    parser.add_argument("--variant-id", required=True, help="Variant ID")
    
    args = parser.parse_args()
    
    success = etl_flow_correlation(args.variant_id)
    return 0 if success else 1

if __name__ == "__main__":
    exit(main()) 