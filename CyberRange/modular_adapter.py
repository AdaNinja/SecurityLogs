#!/usr/bin/env python3
"""
Modular Configuration Adapter
Converts modular configuration to detailed format for compatibility
"""

import yaml
import logging
from typing import Dict, Optional
from parsers.config_parser import ModularConfigParser


class ModularAdapter:
    """
    Adapter to convert modular configuration to detailed format
    for compatibility with existing orchestration system
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.parser = ModularConfigParser()
    
    def load_config(self, config_path: str) -> Optional[Dict]:
        """
        Load configuration and convert if needed
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Dict: Configuration in detailed format
        """
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            # Check if it's modular format (has 'name' at root level)
            if 'name' in config and 'scenario' not in config:
                self.logger.info(f"Detected modular configuration: {config_path}")
                return self.parser.parse_modular_config(config_path)
            else:
                self.logger.info(f"Detected detailed configuration: {config_path}")
                return config
                
        except Exception as e:
            self.logger.error(f"Failed to load configuration {config_path}: {e}")
            return None
    
    def is_modular_format(self, config: Dict) -> bool:
        """
        Check if configuration is in modular format
        
        Args:
            config: Configuration dictionary
            
        Returns:
            bool: True if modular format
        """
        return 'name' in config and 'scenario' not in config


def load_config_with_adapter(config_path: str) -> Optional[Dict]:
    """
    Load configuration with automatic format detection and conversion
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Dict: Configuration in detailed format
    """
    adapter = ModularAdapter()
    return adapter.load_config(config_path)


if __name__ == "__main__":
    # Test the adapter
    adapter = ModularAdapter()
    
    # Test modular config
    config = adapter.load_config("scenarios/modular_demo.yaml")
    if config:
        print("✅ Modular configuration loaded successfully!")
        print(f"   - Scenario: {config.get('scenario', {}).get('name', 'Unknown')}")
        print(f"   - Nodes: {len(config.get('infrastructure', {}).get('nodes', []))}")
    else:
        print("❌ Failed to load modular configuration") 