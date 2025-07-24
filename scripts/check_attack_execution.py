#!/usr/bin/env python3
"""
Attack Execution Check Script
Verify that each step of the attack is executed correctly
"""

import os
import json
import argparse
from datetime import datetime
from typing import Dict, List, Any

def check_attack_phases(variant_id: str) -> Dict[str, Any]:
    """Check each phase of the attack"""
    results = {
        "variant_id": variant_id,
        "timestamp": datetime.now().isoformat(),
        "phases": {},
        "summary": {}
    }
    
    # Check attack log files
    attack_log_path = f"data/logs/{variant_id}/output/attack.log"
    if os.path.exists(attack_log_path):
        results["phases"]["attack_log"] = check_attack_log(attack_log_path)
    
    # Check attack results
    attack_results_path = f"data/processed/{variant_id}/attack_logs/attack_results.jsonl"
    if os.path.exists(attack_results_path):
        results["phases"]["attack_results"] = check_attack_results(attack_results_path)
    
    # Check network scan
    scan_results_path = f"data/logs/{variant_id}/output/scan_results.json"
    if os.path.exists(scan_results_path):
        results["phases"]["network_scan"] = check_network_scan(scan_results_path)
    
    # Check web application logs
    nginx_access_path = f"data/logs/{variant_id}/nginx/access.log"
    if os.path.exists(nginx_access_path):
        results["phases"]["web_logs"] = check_web_logs(nginx_access_path)
    
    # Check data extraction
    extracted_data_path = f"data/logs/{variant_id}/output/extracted_data.html"
    if os.path.exists(extracted_data_path):
        results["phases"]["data_extraction"] = check_data_extraction(extracted_data_path)
    
    # Check PCAP files
    pcap_dir = f"data/logs/{variant_id}/pcap/"
    if os.path.exists(pcap_dir):
        results["phases"]["network_capture"] = check_network_capture(pcap_dir)
    
    # Generate summary
    results["summary"] = generate_summary(results["phases"])
    
    return results

def check_attack_log(log_path: str) -> Dict[str, Any]:
    """Check attack logs"""
    result = {
        "status": "success",
        "phases": [],
        "errors": []
    }
    
    try:
        with open(log_path, 'r') as f:
            lines = f.readlines()
        
        # Check key phases
        phases = {
            "connectivity": "Container Connectivity",
            "reconnaissance": "Network Reconnaissance",
            "enumeration": "Web Application Enumeration", 
            "sql_injection": "Custom SQL Injection",
            "data_extraction": "Data Extraction"
        }
        
        for phase_name, phase_keyword in phases.items():
            phase_lines = [line for line in lines if phase_keyword in line]
            if phase_lines:
                result["phases"].append({
                    "name": phase_name,
                    "status": "executed",
                    "timestamp": extract_timestamp(phase_lines[0]),
                    "details": len(phase_lines)
                })
            else:
                result["phases"].append({
                    "name": phase_name,
                    "status": "not_found",
                    "timestamp": None,
                    "details": 0
                })
        
        # Check errors
        error_lines = [line for line in lines if "ERROR" in line or "FAILED" in line]
        result["errors"] = len(error_lines)
        
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

def check_attack_results(results_path: str) -> Dict[str, Any]:
    """Check attack results"""
    result = {
        "status": "success",
        "total_attacks": 0,
        "successful_attacks": 0,
        "failed_attacks": 0,
        "attack_types": {}
    }
    
    try:
        with open(results_path, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    result["total_attacks"] += 1
                    
                    # Check attack success
                    if data.get("success", False):
                        result["successful_attacks"] += 1
                    else:
                        result["failed_attacks"] += 1
                    
                    # Count attack types
                    attack_type = data.get("attack_type", "unknown")
                    result["attack_types"][attack_type] = result["attack_types"].get(attack_type, 0) + 1
                    
                except json.JSONDecodeError:
                    continue
                    
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

def check_network_scan(scan_path: str) -> Dict[str, Any]:
    """Check network scan results"""
    result = {
        "status": "success",
        "ports_scanned": 0,
        "open_ports": 0,
        "services_found": []
    }
    
    try:
        with open(scan_path, 'r') as f:
            scan_data = json.load(f)
            
        if "ports" in scan_data:
            result["ports_scanned"] = len(scan_data["ports"])
            result["open_ports"] = len([p for p in scan_data["ports"] if p.get("state") == "open"])
            result["services_found"] = [p.get("service", "unknown") for p in scan_data["ports"] if p.get("state") == "open"]
            
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

def check_web_logs(access_log_path: str) -> Dict[str, Any]:
    """Check web application logs"""
    result = {
        "status": "success",
        "total_requests": 0,
        "attack_requests": 0,
        "status_codes": {},
        "endpoints": {}
    }
    
    try:
        with open(access_log_path, 'r') as f:
            for line in f:
                result["total_requests"] += 1
                
                # Check for attack patterns
                if any(pattern in line.lower() for pattern in ["union", "select", "or 1=1", "admin'", "'--"]):
                    result["attack_requests"] += 1
                
                # Parse status code
                parts = line.split()
                if len(parts) >= 9:
                    status_code = parts[8]
                    result["status_codes"][status_code] = result["status_codes"].get(status_code, 0) + 1
                    
                    # Parse endpoint
                    if len(parts) >= 7:
                        endpoint = parts[6].split('?')[0]
                        result["endpoints"][endpoint] = result["endpoints"].get(endpoint, 0) + 1
                        
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

def check_data_extraction(extracted_data_path: str) -> Dict[str, Any]:
    """Check data extraction results"""
    result = {
        "status": "success",
        "file_size": 0,
        "content_length": 0,
        "extracted_tables": 0
    }
    
    try:
        if os.path.exists(extracted_data_path):
            result["file_size"] = os.path.getsize(extracted_data_path)
            
            with open(extracted_data_path, 'r') as f:
                content = f.read()
                result["content_length"] = len(content)
                result["extracted_tables"] = content.count("<table")
                
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

def check_network_capture(pcap_dir: str) -> Dict[str, Any]:
    """Check network capture files"""
    result = {
        "status": "success",
        "pcap_files": [],
        "total_size": 0
    }
    
    try:
        for filename in os.listdir(pcap_dir):
            if filename.endswith('.pcap'):
                file_path = os.path.join(pcap_dir, filename)
                file_size = os.path.getsize(file_path)
                result["pcap_files"].append({
                    "name": filename,
                    "size": file_size
                })
                result["total_size"] += file_size
                
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

def extract_timestamp(line: str) -> str:
    """Extract timestamp from log line"""
    try:
        # Look for ISO format timestamp
        import re
        timestamp_pattern = r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
        match = re.search(timestamp_pattern, line)
        if match:
            return match.group()
    except:
        pass
    return "unknown"

def generate_summary(phases: Dict[str, Any]) -> Dict[str, Any]:
    """Generate summary of all phases"""
    summary = {
        "total_phases": len(phases),
        "successful_phases": 0,
        "failed_phases": 0,
        "phase_details": {}
    }
    
    for phase_name, phase_result in phases.items():
        if isinstance(phase_result, dict):
            status = phase_result.get("status", "unknown")
            if status == "success":
                summary["successful_phases"] += 1
            elif status == "error":
                summary["failed_phases"] += 1
            
            summary["phase_details"][phase_name] = {
                "status": status,
                "details": phase_result
            }
    
    return summary

def print_results(results: Dict[str, Any]):
    """Print formatted results"""
    print("=" * 60)
    print(f"Attack Execution Check Results")
    print(f"Variant: {results['variant_id']}")
    print(f"Timestamp: {results['timestamp']}")
    print("=" * 60)
    
    # Print phase results
    print("\nPhase Results:")
    for phase_name, phase_result in results["phases"].items():
        if isinstance(phase_result, dict):
            status = phase_result.get("status", "unknown")
            status_symbol = "✅" if status == "success" else "❌" if status == "error" else "⚠️"
            print(f"  {status_symbol} {phase_name}: {status}")
            
            # Print phase details
            if "phases" in phase_result:
                for sub_phase in phase_result["phases"]:
                    sub_status = sub_phase.get("status", "unknown")
                    sub_symbol = "✅" if sub_status == "executed" else "❌"
                    print(f"    {sub_symbol} {sub_phase['name']}: {sub_status}")
    
    # Print summary
    print("\nSummary:")
    summary = results["summary"]
    print(f"  Total phases: {summary['total_phases']}")
    print(f"  Successful: {summary['successful_phases']}")
    print(f"  Failed: {summary['failed_phases']}")
    
    # Print recommendations
    print("\nRecommendations:")
    if summary["failed_phases"] > 0:
        print("  ⚠️  Some phases failed. Check logs for details.")
    else:
        print("  ✅ All phases completed successfully.")
    
    print("=" * 60)

def main():
    parser = argparse.ArgumentParser(description="Check attack execution for a variant")
    parser.add_argument("variant_id", help="Variant ID to check")
    parser.add_argument("--output", "-o", help="Output file for results")
    
    args = parser.parse_args()
    
    # Check attack phases
    results = check_attack_phases(args.variant_id)
    
    # Print results
    print_results(results)
    
    # Save results if output file specified
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {args.output}")

if __name__ == "__main__":
    main() 