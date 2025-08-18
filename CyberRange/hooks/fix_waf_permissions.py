#!/usr/bin/env python3
"""
Fix WAF Permissions Hook
Ensures proper permissions for ModSecurity container log directories
"""

import os
import sys
import stat
import logging
from pathlib import Path

def setup_logging():
    """Setup logging for the hook"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

def fix_waf_permissions():
    """Fix permissions for WAF log directories"""
    logger = setup_logging()
    
    logger.info("Fixing WAF permissions for ModSecurity container")
    
    # Get experiment directory from environment
    experiment_dir = os.environ.get('EXPERIMENT_DIR', 'logs')
    
    # Directories that need special permissions for ModSecurity
    waf_dirs = [
        os.path.join(experiment_dir, 'nginx'),
        os.path.join(experiment_dir, 'modsecurity')
    ]
    
    try:
        for dir_path in waf_dirs:
            if os.path.exists(dir_path):
                # Set directory permissions to 777 (read/write/execute for all)
                os.chmod(dir_path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
                logger.info(f"Set permissions 777 on directory: {dir_path}")
                
                # Also set permissions on any existing files
                for root, dirs, files in os.walk(dir_path):
                    for d in dirs:
                        full_path = os.path.join(root, d)
                        os.chmod(full_path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
                        logger.debug(f"Set directory permissions: {full_path}")
                    
                    for f in files:
                        full_path = os.path.join(root, f)
                        os.chmod(full_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH)
                        logger.debug(f"Set file permissions: {full_path}")
            else:
                logger.warning(f"Directory does not exist: {dir_path}")
        
        logger.info("WAF permissions fixed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to fix WAF permissions: {e}")
        return False

def main():
    """Main function"""
    success = fix_waf_permissions()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
