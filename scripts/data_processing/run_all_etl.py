#!/usr/bin/env python3
"""
Unified ETL Script
Run all ETL scripts with consistent variant_id support
"""

import os
import sys
import subprocess
import argparse
from datetime import datetime
import glob

def run_etl_script(script_name, variant_id=None, *args):
    """Run an ETL script with variant_id parameter"""
    script_path = f"scripts/data_processing/{script_name}"
    
    if not os.path.exists(script_path):
        print(f"Warning: ETL script not found: {script_path}")
        return False
    
    cmd = ["python3", script_path]
    
    # Add variant_id if provided
    if variant_id:
        if script_name == "parse_dns_logs.py":
            # DNS parser needs log file and variant_id, and sudo for access
            cmd = ["sudo"] + cmd
            cmd.extend(["/var/log/dnsmasq.log", variant_id])
        else:
            # Other scripts use --variant-id flag
            cmd.extend(["--variant-id", variant_id])
    
    # Add additional arguments
    cmd.extend(args)
    
    print(f"Running: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            print(f"✅ {script_name} completed successfully")
            if result.stdout:
                print(result.stdout)
            return True
        else:
            print(f"❌ {script_name} failed with return code {result.returncode}")
            if result.stderr:
                print(result.stderr)
            return False
    except subprocess.TimeoutExpired:
        print(f"❌ {script_name} timed out")
        return False
    except Exception as e:
        print(f"❌ Error running {script_name}: {e}")
        return False

def run_pcap_analysis(variant_id):
    """Run PCAP analysis for the variant"""
    print(f"\n📊 PCAP Analysis ETL")
    print("-" * 40)
    
    # Find PCAP files for this variant
    pcap_pattern = f"data/logs/{variant_id}/pcap/*.pcap"
    pcap_files = glob.glob(pcap_pattern)
    
    if not pcap_files:
        print(f"⚠️  No PCAP files found for variant: {variant_id}")
        return True
    
    success_count = 0
    total_count = len(pcap_files)
    
    for pcap_file in pcap_files:
        print(f"Processing PCAP file: {os.path.basename(pcap_file)}")
        
        cmd = ["python3", "scripts/data_processing/enhanced_pcap_analyzer.py", pcap_file, "--variant-id", variant_id]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode == 0:
                print(f"✅ PCAP analysis completed for {os.path.basename(pcap_file)}")
                if result.stdout:
                    print(result.stdout)
                success_count += 1
            else:
                print(f"❌ PCAP analysis failed for {os.path.basename(pcap_file)}")
                if result.stderr:
                    print(result.stderr)
        except subprocess.TimeoutExpired:
            print(f"❌ PCAP analysis timed out for {os.path.basename(pcap_file)}")
        except Exception as e:
            print(f"❌ Error analyzing PCAP file {os.path.basename(pcap_file)}: {e}")
    
    print(f"PCAP Analysis Summary: {success_count}/{total_count} files processed")
    return success_count == total_count

def run_all_etl(variant_id=None):
    """Run all ETL scripts in the correct order"""
    print(f"🚀 Starting unified ETL process")
    if variant_id:
        print(f"📋 Using variant_id: {variant_id}")
    print("=" * 60)
    
    # Define ETL scripts in execution order
    etl_scripts = [
        ("etl_host_logs.py", "Host logs ETL"),
        ("etl_container_logs.py", "Container logs ETL"),
        ("etl_application_logs.py", "Application logs ETL"),
        ("etl_webapp_logs.py", "Webapp logs ETL"),
        ("etl_attack_logs.py", "Attack logs ETL"),
        ("parse_dns_logs.py", "DNS logs ETL"),
    ]
    
    success_count = 0
    total_count = len(etl_scripts)
    
    for script_name, description in etl_scripts:
        print(f"\n📊 {description}")
        print("-" * 40)
        
        if run_etl_script(script_name, variant_id):
            success_count += 1
        else:
            print(f"⚠️  {description} failed, continuing with other scripts...")
    
    # Run PCAP analysis if variant_id is provided
    if variant_id:
        if run_pcap_analysis(variant_id):
            success_count += 1
        total_count += 1
    
    # Run data analysis if variant_id is provided
    if variant_id:
        print(f"\n📊 Data Analysis")
        print("-" * 40)
        
        analysis_cmd = ["python3", "scripts/show_extracted_data.py", variant_id]
        print(f"Running: {' '.join(analysis_cmd)}")
        
        try:
            result = subprocess.run(analysis_cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                print(f"✅ Data analysis completed successfully")
                if result.stdout:
                    print(result.stdout)
                success_count += 1
            else:
                print(f"❌ Data analysis failed with return code {result.returncode}")
                if result.stderr:
                    print(result.stderr)
        except subprocess.TimeoutExpired:
            print(f"❌ Data analysis timed out")
        except Exception as e:
            print(f"❌ Error running data analysis: {e}")
        
        total_count += 1
    
    # Create unified dataset if variant_id is provided
    if variant_id:
        print(f"\n📊 Unified Dataset Creation")
        print("-" * 40)
        
        unified_cmd = ["python3", "scripts/data_processing/create_unified_dataset.py", variant_id]
        print(f"Running: {' '.join(unified_cmd)}")
        
        try:
            result = subprocess.run(unified_cmd, capture_output=True, text=True, timeout=600)
            if result.returncode == 0:
                print(f"✅ Unified dataset creation completed successfully")
                if result.stdout:
                    print(result.stdout)
                success_count += 1
            else:
                print(f"❌ Unified dataset creation failed with return code {result.returncode}")
                if result.stderr:
                    print(result.stderr)
        except subprocess.TimeoutExpired:
            print(f"❌ Unified dataset creation timed out")
        except Exception as e:
            print(f"❌ Error creating unified dataset: {e}")
        
        total_count += 1
    
    print("\n" + "=" * 60)
    print(f"📈 ETL Summary:")
    print(f"   Successful: {success_count}/{total_count}")
    print(f"   Failed: {total_count - success_count}/{total_count}")
    
    if success_count == total_count:
        print("✅ All ETL scripts completed successfully!")
        return True
    else:
        print("⚠️  Some ETL scripts failed. Check the output above.")
        return False

def main():
    parser = argparse.ArgumentParser(description="Run all ETL scripts with unified format")
    parser.add_argument("--variant-id", help="Variant ID to add to all records")
    parser.add_argument("--timestamp", help="Timestamp for the ETL run (default: current time)")
    
    args = parser.parse_args()
    
    # Use provided timestamp or current time
    timestamp = args.timestamp or datetime.now().isoformat()
    print(f"🕒 ETL run timestamp: {timestamp}")
    
    # Run all ETL scripts
    success = run_all_etl(args.variant_id)
    
    if success:
        print("\n🎉 ETL process completed successfully!")
        print("📁 Check data/processed/ directory for processed files")
        sys.exit(0)
    else:
        print("\n💥 ETL process completed with errors!")
        sys.exit(1)

if __name__ == "__main__":
    main() 