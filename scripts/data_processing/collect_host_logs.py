#!/usr/bin/env python3
"""
Host Logs Collection Script
Collect system logs from the host machine during experiments
"""

import os
import sys
import subprocess
import shutil
from datetime import datetime

def collect_system_logs(variant_id):
    """Collect system logs for a specific variant"""
    print(f"Collecting host logs for variant: {variant_id}")
    
    # Create variant-specific host logs directory
    host_logs_dir = f"data/logs/{variant_id}/host"
    os.makedirs(host_logs_dir, exist_ok=True)
    
    # List of system log files to collect
    log_files = [
        "/var/log/syslog",
        "/var/log/messages", 
        "/var/log/auth.log",
        "/var/log/kern.log",
        "/var/log/dmesg"
    ]
    
    collected_files = []
    
    for log_file in log_files:
        if os.path.exists(log_file):
            try:
                # Copy log file to variant directory
                dest_file = os.path.join(host_logs_dir, os.path.basename(log_file))
                shutil.copy2(log_file, dest_file)
                collected_files.append(dest_file)
                print(f"Collected: {log_file} -> {dest_file}")
            except Exception as e:
                print(f"Failed to collect {log_file}: {e}")
        else:
            print(f"Log file not found: {log_file}")
    
    # Collect current system information
    try:
        # System info
        with open(os.path.join(host_logs_dir, "system_info.txt"), "w") as f:
            subprocess.run(["uname", "-a"], stdout=f, stderr=subprocess.STDOUT)
        
        # Process list
        with open(os.path.join(host_logs_dir, "processes.txt"), "w") as f:
            subprocess.run(["ps", "aux"], stdout=f, stderr=subprocess.STDOUT)
        
        # Network connections
        with open(os.path.join(host_logs_dir, "netstat.txt"), "w") as f:
            subprocess.run(["netstat", "-tuln"], stdout=f, stderr=subprocess.STDOUT)
        
        collected_files.extend([
            os.path.join(host_logs_dir, "system_info.txt"),
            os.path.join(host_logs_dir, "processes.txt"),
            os.path.join(host_logs_dir, "netstat.txt")
        ])
        print("Collected system information")
    except Exception as e:
        print(f"Failed to collect system info: {e}")
    
    return collected_files

if __name__ == "__main__":
    variant_id = sys.argv[1] if len(sys.argv) > 1 else "default"
    collect_system_logs(variant_id) 