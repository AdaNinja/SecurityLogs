#!/usr/bin/env python3
"""
Cleanup ETL Data
Remove duplicate and intermediate files, keep only final datasets
"""

import os
import shutil
import glob
from pathlib import Path

def cleanup_variant_data(variant_id):
    """Clean up duplicate and intermediate data for a variant"""
    print(f"🧹 Cleaning up data for variant: {variant_id}")
    
    base_path = f"data/processed/{variant_id}"
    if not os.path.exists(base_path):
        print(f"❌ Variant {variant_id} not found")
        return False
    
    # Keep only essential directories and files
    essential_dirs = {
        "datasets": "Final unified datasets (keep all)",
        "analysis": "Flow correlation analysis (keep latest)",
        "security_data": "Attack results (keep latest)"
    }
    
    # Remove duplicate DNS data files (keep only the latest)
    dns_data_dir = f"{base_path}/dns_data"
    if os.path.exists(dns_data_dir):
        dns_files = glob.glob(f"{dns_data_dir}/*.jsonl")
        if len(dns_files) > 1:
            # Keep the latest file
            latest_file = max(dns_files, key=os.path.getctime)
            for file in dns_files:
                if file != latest_file:
                    os.remove(file)
                    print(f"   🗑️  Removed duplicate: {file}")
    
    # Remove intermediate directories that are not essential
    intermediate_dirs = [
        "dns_data",  # Merged into unified dataset
        "proxy_data",  # Merged into unified dataset
        "system_logs",  # Merged into unified dataset
        "pcap"  # Merged into unified dataset
    ]
    
    for dir_name in intermediate_dirs:
        dir_path = f"{base_path}/{dir_name}"
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path)
            print(f"   🗑️  Removed intermediate directory: {dir_name}")
    
    # Keep only the latest files in essential directories
    for dir_name in ["analysis", "security_data"]:
        dir_path = f"{base_path}/{dir_name}"
        if os.path.exists(dir_path):
            files = glob.glob(f"{dir_path}/*")
            if len(files) > 1:
                # Keep the latest file
                latest_file = max(files, key=os.path.getctime)
                for file in files:
                    if file != latest_file:
                        os.remove(file)
                        print(f"   🗑️  Removed duplicate: {os.path.basename(file)}")
    
    print(f"✅ Cleanup completed for {variant_id}")
    return True

def show_data_summary():
    """Show summary of cleaned data"""
    print("\n📊 Data Summary After Cleanup:")
    print("=" * 50)
    
    variants = ["lowscan_stealthy", "lowscan_moderate", "lowscan_aggressive"]
    
    for variant in variants:
        base_path = f"data/processed/{variant}"
        if not os.path.exists(base_path):
            continue
            
        print(f"\n🔍 {variant}:")
        
        # Count files in each directory
        for dir_name in ["datasets", "analysis", "security_data"]:
            dir_path = f"{base_path}/{dir_name}"
            if os.path.exists(dir_path):
                files = glob.glob(f"{dir_path}/*")
                print(f"   {dir_name}: {len(files)} files")
        
        # Show dataset size
        datasets_dir = f"{base_path}/datasets"
        if os.path.exists(datasets_dir):
            csv_files = glob.glob(f"{datasets_dir}/*.csv")
            for csv_file in csv_files:
                size = os.path.getsize(csv_file)
                print(f"   📄 {os.path.basename(csv_file)}: {size/1024:.1f} KB")

def main():
    """Main cleanup function"""
    print("🚀 ETL Data Cleanup")
    print("=" * 50)
    
    variants = ["lowscan_stealthy", "lowscan_moderate", "lowscan_aggressive"]
    
    for variant in variants:
        cleanup_variant_data(variant)
    
    show_data_summary()
    
    print("\n✅ Cleanup completed!")
    print("\n📁 Final structure for each variant:")
    print("   data/processed/{variant}/")
    print("   ├── datasets/          # Final unified datasets")
    print("   ├── analysis/          # Flow correlation")
    print("   └── security_data/     # Attack results")

if __name__ == "__main__":
    main() 