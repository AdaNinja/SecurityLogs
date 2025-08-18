#!/usr/bin/env python3
"""
Auto Parse Logs Hook
Automatically parses collected logs to CSV format
"""

import os
import sys
import subprocess
import logging
from pathlib import Path

def setup_logging():
    """Setup logging for the hook"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

def auto_parse_logs():
    """Automatically parse all collected logs to CSV format"""
    logger = setup_logging()
    
    logger.info("Starting automatic log parsing")
    
    # Get scenario context from environment
    scenario_name = os.environ.get('scenario_name', 'unknown')
    logger.info(f"Parsing logs for scenario: {scenario_name}")
    
    # Check if logs directory exists
    logs_dir = Path('logs')
    if not logs_dir.exists():
        logger.error("Logs directory not found")
        return False
    
    # Check if parse_logs.py exists
    parse_script = Path('parsers/parse_logs.py')
    if not parse_script.exists():
        logger.error("parse_logs.py not found")
        return False
    
    try:
        # Run the parse_logs.py script with explicit arguments
        logger.info("Executing parse_logs.py...")
        # Get experiment directory from environment
        experiment_dir = os.environ.get('EXPERIMENT_DIR', 'logs')
        
        # Extract experiment name from experiment_dir for output structure
        if '/' in experiment_dir:
            experiment_name = experiment_dir.split('/')[-1]
        else:
            experiment_name = experiment_dir
            
        # Create matching output directory structure
        output_dir = f'output/{experiment_name}'
        os.makedirs(output_dir, exist_ok=True)
        
        cmd = [
            sys.executable, str(parse_script),
            '--input-dir', experiment_dir,
            '--output-dir', output_dir,
            '--log-type', 'all'
        ]
        logger.info(f"Command: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True, 
            text=True, 
            timeout=300,
            cwd=Path.cwd()  # Ensure we're in the right directory
        )
        
        # Check if parsing was successful (warnings are OK)
        if result.returncode == 0:
            logger.info("Log parsing completed successfully")
            if result.stdout.strip():
                logger.info(f"Output: {result.stdout}")
            return True
        elif result.returncode == 1 and "Some files failed to parse" in result.stderr:
            # This is a warning, not an error - parsing was mostly successful
            logger.info("Log parsing completed with warnings")
            if result.stderr.strip():
                logger.info(f"Warnings: {result.stderr}")
            if result.stdout.strip():
                logger.info(f"Output: {result.stdout}")
            return True
        else:
            logger.error(f"Log parsing failed with return code: {result.returncode}")
            if result.stderr.strip():
                logger.error(f"Error output: {result.stderr}")
            if result.stdout.strip():
                logger.info(f"Standard output: {result.stdout}")
            return False
            
    except subprocess.TimeoutExpired:
        logger.error("Log parsing timed out")
        return False
    except Exception as e:
        logger.error(f"Log parsing failed: {e}")
        return False

def main():
    """Main function"""
    success = auto_parse_logs()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 