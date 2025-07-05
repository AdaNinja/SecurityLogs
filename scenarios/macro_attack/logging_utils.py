#!/usr/bin/env python3
"""
Logging utilities for macro attack simulation
Records traditional system logs for different attack complexity levels
"""

import os
import time
import json
import subprocess
import socket
import threading
from datetime import datetime
from pathlib import Path

class AttackLogger:
    def __init__(self, output_dir, attack_type):
        self.output_dir = Path(output_dir)
        self.attack_type = attack_type
        self.log_file = self.output_dir / f"{attack_type}_system_logs.jsonl"
        self.network_log_file = self.output_dir / f"{attack_type}_network_logs.jsonl"
        self.file_log_file = self.output_dir / f"{attack_type}_file_logs.jsonl"
        self.process_log_file = self.output_dir / f"{attack_type}_process_logs.jsonl"
        
        # Create output directory if it doesn't exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize log files
        self._init_log_files()
    
    def _init_log_files(self):
        """Initialize log files with headers"""
        headers = {
            self.log_file: {"type": "system_log", "attack_type": self.attack_type, "timestamp": datetime.now().isoformat()},
            self.network_log_file: {"type": "network_log", "attack_type": self.attack_type, "timestamp": datetime.now().isoformat()},
            self.file_log_file: {"type": "file_log", "attack_type": self.attack_type, "timestamp": datetime.now().isoformat()},
            self.process_log_file: {"type": "process_log", "attack_type": self.attack_type, "timestamp": datetime.now().isoformat()}
        }
        
        for log_file, header in headers.items():
            with open(log_file, 'w') as f:
                f.write(json.dumps(header) + '\n')
    
    def log_system_event(self, event_type, details, severity="INFO"):
        """Log system events"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "severity": severity,
            "attack_type": self.attack_type,
            "details": details
        }
        
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def log_network_activity(self, connection_type, source, destination, port=None, data_size=None):
        """Log network connections and activities"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "connection_type": connection_type,
            "source": source,
            "destination": destination,
            "port": port,
            "data_size": data_size,
            "attack_type": self.attack_type
        }
        
        with open(self.network_log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def log_file_operation(self, operation, file_path, file_size=None, permissions=None):
        """Log file operations"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation,
            "file_path": str(file_path),
            "file_size": file_size,
            "permissions": permissions,
            "attack_type": self.attack_type
        }
        
        with open(self.file_log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def log_process_creation(self, process_name, pid, parent_pid=None, command_line=None):
        """Log process creation events"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "process_name": process_name,
            "pid": pid,
            "parent_pid": parent_pid,
            "command_line": command_line,
            "attack_type": self.attack_type
        }
        
        with open(self.process_log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def simulate_network_scan(self, target_hosts, ports):
        """Simulate network scanning activity"""
        for host in target_hosts:
            for port in ports:
                try:
                    # Simulate connection attempt
                    self.log_network_activity("scan", "attacker", host, port, 0)
                    time.sleep(0.1)  # Small delay to simulate real scanning
                except Exception as e:
                    self.log_system_event("network_scan_error", str(e), "ERROR")
    
    def simulate_file_encryption(self, file_path, encryption_type):
        """Simulate file encryption activity"""
        self.log_file_operation("read", file_path)
        self.log_system_event("encryption_start", f"Starting {encryption_type} encryption of {file_path}")
        
        # Simulate encryption process
        time.sleep(0.2)
        
        self.log_file_operation("write", file_path, 1024, "rw-r--r--")
        self.log_system_event("encryption_complete", f"Completed {encryption_type} encryption of {file_path}")
    
    def simulate_persistence_mechanism(self, mechanism_type, target_path):
        """Simulate persistence mechanism installation"""
        self.log_system_event("persistence_install", f"Installing {mechanism_type} persistence mechanism")
        self.log_file_operation("create", target_path)
        self.log_system_event("persistence_complete", f"Persistence mechanism installed at {target_path}")
    
    def simulate_command_execution(self, command, output=None):
        """Simulate command execution"""
        self.log_process_creation("bash", 12345, 1234, command)
        self.log_system_event("command_execution", f"Executed command: {command}")
        
        if output:
            self.log_system_event("command_output", f"Output: {output}")
        
        return output
    
    def simulate_registry_modification(self, key_path, value_name, value_data):
        """Simulate registry modification (Windows) or config modification (Unix)"""
        self.log_system_event("registry_modify", f"Modifying {key_path}:{value_name}")
        self.log_file_operation("modify", f"/etc/config/{key_path}")
        self.log_system_event("registry_complete", f"Registry modification completed")

def create_log_summary(logger, output_dir):
    """Create a summary of all logs"""
    summary_file = Path(output_dir) / f"{logger.attack_type}_log_summary.json"
    
    # Count log entries
    log_counts = {}
    for log_file in [logger.log_file, logger.network_log_file, logger.file_log_file, logger.process_log_file]:
        if log_file.exists():
            with open(log_file, 'r') as f:
                lines = f.readlines()
                log_counts[log_file.name] = len(lines) - 1  # Subtract header
    
    summary = {
        "attack_type": logger.attack_type,
        "timestamp": datetime.now().isoformat(),
        "log_counts": log_counts,
        "total_events": sum(log_counts.values()),
        "log_files": [
            str(logger.log_file),
            str(logger.network_log_file),
            str(logger.file_log_file),
            str(logger.process_log_file)
        ]
    }
    
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    return summary 