#!/usr/bin/env python3
"""
Setup Experiment Directories Hook
"""

import os
import sys
import logging
import yaml
from pathlib import Path
from datetime import datetime

def setup_logging():
    """Setup logging for the hook"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

def get_experiment_name_from_config(config_path):
    """Extract experiment name from scenario configuration file"""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        # Use scenario.name if available
        if 'scenario' in config and 'name' in config['scenario']:
            return config['scenario']['name']
        
        # Otherwise use file name
        return Path(config_path).stem
        
    except Exception as e:
        logger = setup_logging()
        logger.warning(f"Could not extract experiment name from {config_path}: {e}")
        return Path(config_path).stem

def create_experiment_directories(experiment_name, timestamp=None):
    """Create experiment-specific directory structure on host"""
    logger = setup_logging()
    
    if timestamp:
        full_experiment_name = f"{experiment_name}_{timestamp}"
    else:
        full_experiment_name = experiment_name
    
    # Only create host-side directories that containers will mount
    # Container-specific directories will be created by start_services.sh
    directories = [
        f"logs/{full_experiment_name}",
        f"output/{full_experiment_name}"
    ]
    
    created_dirs = []
    
    for directory in directories:
        try:
            Path(directory).mkdir(parents=True, exist_ok=True)
            created_dirs.append(directory)
            logger.info(f"✅ Created host directory: {directory}")
        except Exception as e:
            logger.error(f"❌ Failed to create directory {directory}: {e}")
    
    # Ensure base directories exist (containers will create subdirectories)
    base_dirs = ["exfiltrated_data", "shared_data"]
    for base_dir in base_dirs:
        try:
            Path(base_dir).mkdir(exist_ok=True)
            logger.info(f"✅ Ensured base directory exists: {base_dir}")
        except Exception as e:
            logger.error(f"❌ Failed to create base directory {base_dir}: {e}")
    
    return created_dirs, full_experiment_name

# Data organization is now handled by start_services.sh inside containers
# This ensures proper handling of container-specific paths and permissions

def create_experiment_metadata(experiment_name, full_experiment_name, config_path):
    """Create experiment metadata file"""
    logger = setup_logging()
    
    metadata = {
        "experiment_name": experiment_name,
        "full_experiment_name": full_experiment_name,
        "config_file": str(config_path),
        "created_at": datetime.now().isoformat(),
        "directories": {
            "exfiltrated_data": f"exfiltrated_data/{full_experiment_name}",
            "shared_data": f"shared_data/{full_experiment_name}",
            "logs": f"logs/{full_experiment_name}",
            "output": f"output/{full_experiment_name}"
        }
    }
    
    # Save metadata
    metadata_file = Path(f"output/{full_experiment_name}/experiment_metadata.json")
    try:
        import json
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        logger.info(f"✅ Created experiment metadata: {metadata_file}")
    except Exception as e:
        logger.error(f"❌ Failed to create metadata file: {e}")

def main():
    """Main function - Hook entry point"""
    logger = setup_logging()
    
    # Get command line arguments
    if len(sys.argv) < 2:
        logger.error("Usage: python setup_experiment_directories.py <config_file> [timestamp]")
        sys.exit(1)
    
    config_path = sys.argv[1]
    timestamp = sys.argv[2] if len(sys.argv) > 2 else datetime.now().strftime("%Y%m%d_%H%M%S")
    
    logger.info(f"🚀 Setting up experiment directories for: {config_path}")
    
    # Extract experiment name
    experiment_name = get_experiment_name_from_config(config_path)
    logger.info(f"📋 Experiment name: {experiment_name}")
    
    # Create directory structure
    created_dirs, full_experiment_name = create_experiment_directories(experiment_name, timestamp)
    
    # Create metadata
    create_experiment_metadata(experiment_name, full_experiment_name, config_path)
    
    logger.info("📝 Note: Data organization will be handled by containers during startup")
    
    # Output results for other scripts
    print(f"EXPERIMENT_NAME={experiment_name}")
    print(f"FULL_EXPERIMENT_NAME={full_experiment_name}")
    print(f"CREATED_DIRS={','.join(created_dirs)}")
    
    logger.info(f"✅ Experiment directory setup completed for: {full_experiment_name}")

if __name__ == "__main__":
    main()
