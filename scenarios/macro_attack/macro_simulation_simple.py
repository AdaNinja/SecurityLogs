#!/usr/bin/env python3
"""
Simple Macro Attack Simulation
Basic level attack with minimal obfuscation and traditional logging
"""

import os
import time
import json
import base64
import random
import subprocess
from datetime import datetime
from pathlib import Path
from logging_utils import AttackLogger, create_log_summary

def create_background_activity(output_dir, logger):
    """Create basic background activity files"""
    logger.log_system_event("background_activity_start", "Starting background activity simulation")
    
    # Create basic document files
    documents = [
        ("test_document.txt", "This is a test document for daily work activities."),
        ("test_document_backup.txt", "Backup copy of the test document for safety.")
    ]
    
    for filename, content in documents:
        file_path = output_dir / filename
        with open(file_path, 'w') as f:
            f.write(content)
        
        logger.log_file_operation("create", file_path, len(content), "rw-r--r--")
        logger.log_system_event("file_created", f"Created background file: {filename}")
    
    logger.log_system_event("background_activity_complete", "Background activity simulation completed")

def execute_simple_attack(output_dir, logger):
    """Execute simple macro attack with basic persistence"""
    logger.log_system_event("attack_start", "Starting simple macro attack execution")
    
    # Create simple macro test file
    macro_content = f"""Macro attack test file created at {datetime.now()}
User: {os.getenv('USER', 'unknown')}
Working directory: {os.getcwd()}"""
    
    macro_file = output_dir / "macro_test_simple.txt"
    with open(macro_file, 'w') as f:
        f.write(macro_content)
    
    logger.log_file_operation("create", macro_file, len(macro_content), "rw-r--r--")
    logger.log_system_event("macro_created", "Simple macro file created")
    
    # Create basic persistence files
    for i in range(3):
        persistence_file = output_dir / f"macro_persistence_{i}.txt"
        persistence_content = f"Persistence mechanism {i} - {datetime.now()}"
        
        with open(persistence_file, 'w') as f:
            f.write(persistence_content)
        
        logger.log_file_operation("create", persistence_file, len(persistence_content), "rw-r--r--")
        logger.simulate_persistence_mechanism("file_based", str(persistence_file))
    
    # Simulate basic command execution
    commands = [
        "whoami",
        "pwd",
        "ls -la"
    ]
    
    for cmd in commands:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            logger.simulate_command_execution(cmd, result.stdout[:100])
        except Exception as e:
            logger.log_system_event("command_error", f"Error executing {cmd}: {str(e)}", "ERROR")
    
    logger.log_system_event("attack_complete", "Simple macro attack execution completed")

def main():
    """Main execution function"""
    # Setup
    output_dir = Path("output/simple")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize logger
    logger = AttackLogger(output_dir, "simple")
    logger.log_system_event("simulation_start", "Simple macro attack simulation started")
    
    try:
        # Phase 1: Background Activity
        logger.log_system_event("phase_start", "Phase 1: Background Activity")
        create_background_activity(output_dir, logger)
        time.sleep(1)
        
        # Phase 2: Attack Execution
        logger.log_system_event("phase_start", "Phase 2: Attack Execution")
        execute_simple_attack(output_dir, logger)
        time.sleep(1)
        
        # Phase 3: Cleanup and Logging
        logger.log_system_event("phase_start", "Phase 3: Cleanup and Logging")
        
        # Create log summary
        summary = create_log_summary(logger, output_dir)
        logger.log_system_event("summary_created", f"Log summary created with {summary['total_events']} total events")
        
        print(f"Simple macro attack simulation completed!")
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