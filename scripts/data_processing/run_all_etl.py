#!/usr/bin/env python3
"""
Main ETL Runner
Run all ETL scripts in the correct order
"""

import os
import sys
import argparse
import subprocess
from typing import List, Dict, Any
# Fix relative import issue
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from config import get_config

def run_etl_script(script_name: str, variant_id: str) -> Dict[str, Any]:
    """Run a single ETL script"""
    print(f"Running {script_name} for variant {variant_id}...")
    
    try:
        # Import and run the ETL function
        if script_name == "etl_attack_logs.py":
            from etl_attack_logs import etl_attack_logs
            result = etl_attack_logs(variant_id)
        elif script_name == "etl_application_logs.py":
            from etl_application_logs import etl_application_logs
            result = etl_application_logs(variant_id)
        elif script_name == "etl_container_logs.py":
            from etl_container_logs import etl_container_logs
            result = etl_container_logs(variant_id)
        elif script_name == "etl_host_logs.py":
            from etl_host_logs import etl_host_logs
            result = etl_host_logs(variant_id)
        elif script_name == "parse_dns_logs.py":
            print(f"⚠️  Skipping {script_name} - DNS processing handled by etl_dns_proxy_logs.py")
            return {"success": True, "script": script_name, "skipped": True}
        elif script_name == "enhanced_pcap_analyzer.py":
            from enhanced_pcap_analyzer import enhanced_pcap_analyzer
            result = enhanced_pcap_analyzer(variant_id)
        elif script_name == "etl_dns_proxy_logs.py":
            from etl_dns_proxy_logs import etl_dns_proxy_logs
            result = etl_dns_proxy_logs(variant_id)
        elif script_name == "etl_http_proxy_logs.py":
            from etl_http_proxy_logs import etl_http_proxy_logs
            result = etl_http_proxy_logs(variant_id)
        elif script_name == "etl_flow_correlation.py":
            from etl_flow_correlation import etl_flow_correlation
            result = etl_flow_correlation(variant_id)
        elif script_name == "create_unified_dataset.py":
            from create_unified_dataset import create_unified_dataset
            result = create_unified_dataset(variant_id)
        elif script_name == "create_simplified_view.py":
            from create_simplified_view import create_simplified_view
            result = create_simplified_view(variant_id)
        else:
            print(f"❌ Unknown script: {script_name}")
            return {"success": False, "error": f"Unknown script: {script_name}"}
        
        if result:
            print(f"✅ {script_name} completed successfully")
            return {"success": True, "script": script_name}
        else:
            print(f"❌ {script_name} failed")
            return {"success": False, "script": script_name, "error": "Script returned False"}
            
    except Exception as e:
        print(f"❌ {script_name} failed with error: {e}")
        return {"success": False, "script": script_name, "error": str(e)}

def run_all_etl(variant_id: str) -> bool:
    """Run all ETL scripts in order"""
    print(f"🚀 Starting ETL processing for variant: {variant_id}")
    print("=" * 60)
    
    # Get configuration and create directories
    config = get_config(variant_id)
    config.create_directories()
    print("📁 All directories created successfully")
    
    # Define ETL script execution order
    etl_scripts = [
        "etl_attack_logs.py",
        "etl_application_logs.py", 
        "etl_container_logs.py",
        "etl_host_logs.py",
        "enhanced_pcap_analyzer.py",
        "etl_dns_proxy_logs.py",
        "etl_http_proxy_logs.py",
        "etl_flow_correlation.py",
        "create_unified_dataset.py",
        "create_simplified_view.py"
    ]
    
    results = []
    successful = 0
    failed = 0
    
    for script in etl_scripts:
        result = run_etl_script(script, variant_id)
        results.append(result)
        
        if result["success"]:
            successful += 1
        else:
            failed += 1
    
    # Print summary
    print("=" * 60)
    print(f"📊 ETL Processing Summary:")
    print(f"   Total scripts: {len(etl_scripts)}")
    print(f"   Successful: {successful}")
    print(f"   Failed: {failed}")
    print(f"   Success rate: {(successful/len(etl_scripts)*100):.1f}%")
    
    if failed == 0:
        print("✅ All ETL processing completed successfully!")
        return True
    else:
        print("⚠️  Some ETL scripts failed. Check the output above.")
        return False

def main():
    parser = argparse.ArgumentParser(description="Run all ETL scripts")
    parser.add_argument("--variant-id", required=True, help="Variant ID")
    
    args = parser.parse_args()
    
    success = run_all_etl(args.variant_id)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 