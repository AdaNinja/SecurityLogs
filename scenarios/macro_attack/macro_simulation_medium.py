#!/usr/bin/env python3
"""
Medium Macro Attack Simulation
Intermediate level attack with basic obfuscation and enhanced logging
"""

import os
import time
import json
import base64
import random
import subprocess
import requests
from datetime import datetime
from pathlib import Path
from logging_utils import AttackLogger, create_log_summary

def create_background_activity(output_dir, logger):
    """Create medium-level background activity files"""
    logger.log_system_event("background_activity_start", "Starting medium-level background activity simulation")
    
    # Create office documents
    documents = [
        ("budget_report.txt", "Q2 Budget Report - Revenue increased by 15% compared to Q1"),
        ("project_proposal.txt", "New project proposal for client expansion in European market"),
        ("meeting_notes.txt", "Weekly team meeting notes - discussed upcoming product launch"),
        ("draft_email.txt", "Draft email to stakeholders regarding quarterly performance")
    ]
    
    for filename, content in documents:
        file_path = output_dir / filename
        with open(file_path, 'w') as f:
            f.write(content)
        
        logger.log_file_operation("create", file_path, len(content), "rw-r--r--")
        logger.log_system_event("file_created", f"Created background file: {filename}")
    
    # Create backup files
    for filename in ["budget_report.txt", "meeting_notes.txt", "project_proposal.txt"]:
        backup_path = output_dir / f"{filename}.backup"
        original_path = output_dir / filename
        
        if original_path.exists():
            with open(original_path, 'r') as f:
                content = f.read()
            with open(backup_path, 'w') as f:
                f.write(content)
            
            logger.log_file_operation("create", backup_path, len(content), "rw-r--r--")
            logger.log_system_event("backup_created", f"Created backup: {filename}.backup")
    
    # Simulate web browsing activity
    logger.log_system_event("web_browsing_start", "Starting web browsing simulation")
    
    websites = [
        ("https://httpbin.org/get", "email_check"),
        ("https://httpbin.org/status/200", "news_site"),
        ("https://httpbin.org/delay/1", "social_media"),
        ("https://httpbin.org/user-agent", "work_portal")
    ]
    
    for url, activity in websites:
        try:
            response = requests.get(url, timeout=5)
            logger.log_network_activity("http_get", "user", url, 80, len(response.content))
            logger.log_system_event("web_activity", f"Visited {url} for {activity}")
        except Exception as e:
            logger.log_system_event("web_activity_error", f"Failed to visit {url}: {str(e)}", "WARNING")
    
    logger.log_system_event("background_activity_complete", "Medium-level background activity simulation completed")

def execute_medium_attack(output_dir, logger):
    """Execute medium-level macro attack with obfuscation"""
    logger.log_system_event("attack_start", "Starting medium-level macro attack execution")
    
    # Create obfuscated macro content
    original_macro = "This is the original macro content that needs obfuscation"
    obfuscated_macro = base64.b64encode(original_macro.encode()).decode()
    
    obfuscated_file = output_dir / "obfuscated_macro.txt"
    with open(obfuscated_file, 'w') as f:
        f.write(obfuscated_macro)
    
    logger.log_file_operation("create", obfuscated_file, len(obfuscated_macro), "rw-r--r--")
    logger.log_system_event("obfuscation_applied", "Applied Base64 obfuscation to macro content")
    
    # Create encrypted configuration
    config_data = {
        "target": "internal_systems",
        "method": "encrypted_payload",
        "timestamp": datetime.now().isoformat()
    }
    
    config_file = output_dir / "registry_modification.json"
    with open(config_file, 'w') as f:
        json.dump(config_data, f, indent=2)
    
    logger.log_file_operation("create", config_file, len(json.dumps(config_data)), "rw-r--r--")
    logger.simulate_registry_modification("HKEY_CURRENT_USER\\Software\\MacroApp", "Config", str(config_data))
    
    # Create persistence script
    persistence_script = """#!/bin/bash
# Persistence mechanism for medium-level attack
echo "Installing persistence mechanism..."
sleep 2
echo "Persistence mechanism installed successfully"
"""
    
    script_file = output_dir / "macro_persistence.sh"
    with open(script_file, 'w') as f:
        f.write(persistence_script)
    
    # Make script executable
    os.chmod(script_file, 0o755)
    logger.log_file_operation("create", script_file, len(persistence_script), "rwxr-xr-x")
    logger.simulate_persistence_mechanism("script_based", str(script_file))
    
    # Simulate file encryption
    files_to_encrypt = ["budget_report.txt", "project_proposal.txt"]
    for filename in files_to_encrypt:
        file_path = output_dir / filename
        if file_path.exists():
            logger.simulate_file_encryption(file_path, "AES-128")
    
    # Simulate network reconnaissance
    logger.log_system_event("network_recon_start", "Starting network reconnaissance")
    
    target_hosts = ["192.168.1.1", "192.168.1.10", "192.168.1.100"]
    target_ports = [22, 80, 443, 3389]
    
    logger.simulate_network_scan(target_hosts, target_ports)
    logger.log_system_event("network_recon_complete", "Network reconnaissance completed")
    
    # Execute medium-level commands
    commands = [
        "whoami && id",
        "ps aux | grep -i macro",
        "netstat -tuln | head -10",
        "find /tmp -name '*.tmp' -type f"
    ]
    
    for cmd in commands:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            logger.simulate_command_execution(cmd, result.stdout[:200])
        except Exception as e:
            logger.log_system_event("command_error", f"Error executing {cmd}: {str(e)}", "ERROR")
    
    # Create social engineering file
    social_engineering_content = {
        "type": "social_engineering",
        "method": "phishing_simulation",
        "target": "employees",
        "content": "Urgent system update required - please click here"
    }
    
    se_file = output_dir / "social_engineering.json"
    with open(se_file, 'w') as f:
        json.dump(social_engineering_content, f, indent=2)
    
    logger.log_file_operation("create", se_file, len(json.dumps(social_engineering_content)), "rw-r--r--")
    logger.log_system_event("social_engineering_created", "Social engineering payload created")
    
    logger.log_system_event("attack_complete", "Medium-level macro attack execution completed")

def main():
    """Main execution function"""
    # Setup
    output_dir = Path("output/medium")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize logger
    logger = AttackLogger(output_dir, "medium")
    logger.log_system_event("simulation_start", "Medium macro attack simulation started")
    
    try:
        # Phase 1: Background Activity
        logger.log_system_event("phase_start", "Phase 1: Background Activity")
        create_background_activity(output_dir, logger)
        time.sleep(2)
        
        # Phase 2: Attack Execution
        logger.log_system_event("phase_start", "Phase 2: Attack Execution")
        execute_medium_attack(output_dir, logger)
        time.sleep(2)
        
        # Phase 3: Cleanup and Logging
        logger.log_system_event("phase_start", "Phase 3: Cleanup and Logging")
        
        # Create log summary
        summary = create_log_summary(logger, output_dir)
        logger.log_system_event("summary_created", f"Log summary created with {summary['total_events']} total events")
        
        print(f"Medium macro attack simulation completed!")
        print(f"Output directory: {output_dir}")
        print(f"Total log events: {summary['total_events']}")
        print(f"Log files created:")
        for log_file in summary['log_files']:
            print(f"  - {log_file}")
        
    except Exception as e:
        logger.log_system_event("simulation_error", f"Simulation failed: {str(e)}", "ERROR")
        print(f"Error during simulation: {e}")
        raise

if __name__ == "__main__":
    main() 