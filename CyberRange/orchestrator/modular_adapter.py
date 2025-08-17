#!/usr/bin/env python3
"""
Modular Configuration Adapter for CyberRange
Provides flexible configuration loading and conversion capabilities
"""

import os
import yaml
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path


class ConfigurationAdapter:
    """
    Adapter for handling different configuration formats and providing defaults
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.default_config = self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Get default configuration template"""
        project_root = self._get_project_root()
        
        return {
            'scenario': {
                'name': 'default-scenario',
                'description': 'Default scenario configuration',
                'duration': 300,
                'random_seed': 12345
            },
            'infrastructure': {
                'networks': [
                    {
                        'name': 'internal-net',
                        'driver': 'bridge',
                        'subnet': '172.27.0.0/16',
                        'gateway': '172.27.0.1'
                    },
                    {
                        'name': 'external-net',
                        'driver': 'bridge',
                        'subnet': '172.28.0.0/16',
                        'gateway': '172.28.0.1'
                    }
                ],
                'nodes': [
                    {
                        'name': 'juice-shop',
                        'role': 'target',
                        'image': 'bkimminich/juice-shop',
                        'networks': ['internal-net', 'external-net'],
                        'ports': ['3000:3000'],
                        'environment': ['NODE_ENV=production'],
                        'volumes': []
                    },
                    {
                        'name': 'nginx',
                        'role': 'proxy',
                        'image': 'nginx:alpine',
                        'networks': ['internal-net', 'external-net'],
                        'network_aliases': {'internal-net': ['fancystore.com'], 'external-net': ['fancystore.com']},
                        'ports': ['80:80'],
                        'environment': [],
                        'volumes': [
                            f"{project_root}/scenario-securitylogs/confs/nginx/nginx.conf:/etc/nginx/nginx.conf:ro",
                            f"{project_root}/logs/nginx:/var/log/nginx"
                        ]
                    },
                    {
                        'name': 'attacker',
                        'role': 'attacker',
                        'image': 'ras-attacker:latest',
                        'networks': ['internal-net'],
                        'environment': [
                            'TARGET_URL=http://fancystore.com',
                            'TARGET_HOST=fancystore.com',
                            'TARGET_PORT=80'
                        ],
                        'volumes': [
                            f"{project_root}/scenario-securitylogs/confs/attacker:/scripts",
                            f"{project_root}/logs/attacker:/logs"
                        ]
                    },
                    {
                        'name': 'benign_user',
                        'role': 'user',
                        'image': 'python:3.9-slim',
                        'command': 'tail -f /dev/null',
                        'networks': ['internal-net'],
                        'environment': [
                            'TARGET_URL=http://fancystore.com',
                            'USER_TYPE=normal'
                        ],
                        'volumes': [
                            f"{project_root}/scenario-securitylogs/confs/user:/scripts",
                            f"{project_root}/logs/benign_user:/logs"
                        ]
                    }
                ]
            },
            'behaviors': {
                'attacks': [],
                'benign_traffic': []
            },
            'data_collection': {
                'logs': [
                    {
                        'source': 'nginx',
                        'path': '/var/log/nginx/detailed.log',
                        'output': 'nginx_detailed.csv',
                        'parser': 'nginx_parser',
                        'real_time': True
                    },
                    {
                        'source': 'attacker',
                        'path': '/logs/attack.log',
                        'output': 'attack_log.csv',
                        'parser': 'attacker_parser',
                        'real_time': True
                    },
                    {
                        'source': 'benign_user',
                        'path': '/logs/user.log',
                        'output': 'user_behavior.csv',
                        'parser': 'user_parser',
                        'real_time': True
                    }
                ],
                'network': [
                    {
                        'interface': 'any',
                        'filter': 'net 172.27.0.0/16 or net 172.28.0.0/16',
                        'output': 'network_traffic.pcap',
                        'capture_size': '100MB'
                    }
                ],
                'system': []
            },
            'hooks': {
                'pre_scenario': [],
                'post_node_start': [
                    {
                        'name': 'verify_juice_shop',
                        'script': './hooks/verify_juice_shop.py',
                        'timeout': 30
                    }
                ],
                'post_collection': [
                    {
                        'name': 'auto_parse_logs',
                        'script': './hooks/auto_parse_logs.py',
                        'timeout': 300
                    },
                    {
                        'name': 'setup_basic',
                        'script': './hooks/setup_basic.sh',
                        'timeout': 60
                    }
                ],
                'post_scenario': []
            },
            'monitoring': {
                'metrics': [
                    {
                        'name': 'container_health',
                        'interval': 30,
                        'alert_threshold': 0.8
                    },
                    {
                        'name': 'attack_success_rate',
                        'interval': 60,
                        'alert_threshold': 0.5
                    }
                ],
                'alerts': [
                    {
                        'condition': 'container_down',
                        'action': 'restart_container',
                        'max_attempts': 3
                    }
                ]
            },
            'output': {
                'base_dir': 'data',
                'formats': ['csv', 'json'],
                'compression': False,
                'retention': {
                    'days': 7,
                    'max_size': '5GB'
                }
            }
        }
    
    def _get_project_root(self) -> str:
        """Get the project root directory"""
        # Go up from orchestrator to project root
        return str(Path(__file__).parent.parent.absolute())
    
    def load_and_adapt_config(self, config_path: str) -> Optional[Dict]:
        """
        Load configuration file and adapt it to the standard format
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Dict: Adapted configuration or None if failed
        """
        try:
            # Load the raw configuration
            with open(config_path, 'r', encoding='utf-8') as f:
                raw_config = yaml.safe_load(f)
            
            if not raw_config:
                self.logger.error("Configuration file is empty")
                return None
            
            # Adapt the configuration
            adapted_config = self._adapt_configuration(raw_config)
            
            # Validate the adapted configuration
            if self._validate_adapted_config(adapted_config):
                self.logger.info(f"Successfully adapted configuration from: {config_path}")
                return adapted_config
            else:
                self.logger.error("Configuration validation failed after adaptation")
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to load and adapt configuration: {e}")
            return None
    
    def _adapt_configuration(self, raw_config: Dict) -> Dict:
        """
        Adapt raw configuration to standard format
        
        Args:
            raw_config: Raw configuration loaded from file
            
        Returns:
            Dict: Adapted configuration
        """
        # Start with default configuration as base
        adapted_config = self._deep_copy_dict(self.default_config)
        
        # Merge user configuration
        adapted_config = self._deep_merge_dicts(adapted_config, raw_config)
        
        # Apply specific adaptations
        adapted_config = self._adapt_attack_behaviors(adapted_config)
        adapted_config = self._adapt_benign_behaviors(adapted_config)
        adapted_config = self._adapt_volume_paths(adapted_config)
        
        return adapted_config
    
    def _adapt_attack_behaviors(self, config: Dict) -> Dict:
        """Adapt attack behavior configuration"""
        try:
            scenario = config.get('scenario', {})
            attack_types = scenario.get('attack_types', [])
            waf_mode = scenario.get('waf_mode', 'off')
            
            # Only generate attacks if behaviors.attacks is not already defined
            existing_attacks = config.get('behaviors', {}).get('attacks', [])
            
            if attack_types and not existing_attacks:
                self.logger.info("Generating default attack behaviors from attack_types")
                attacks = []
                for attack_type in attack_types:
                    attack_config = {
                        'name': f'{attack_type}_attack',
                        'node': 'attacker',
                        'duration': 20,
                        'interval': 1,
                        'script': '/scripts/attack.sh',
                        'script_args': ['--attack-type', attack_type, '--waf-mode', waf_mode],
                        'payload_config': {
                            'files': [f'/scripts/attacks/{attack_type}.txt'],
                            'lines': [1, 3]
                        }
                    }
                    attacks.append(attack_config)
                
                config['behaviors']['attacks'] = attacks
            elif existing_attacks:
                self.logger.info(f"Using existing attack behaviors ({len(existing_attacks)} attacks defined)")
        
        except Exception as e:
            self.logger.warning(f"Failed to adapt attack behaviors: {e}")
        
        return config
    
    def _adapt_benign_behaviors(self, config: Dict) -> Dict:
        """Adapt benign traffic behavior configuration"""
        try:
            scenario = config.get('scenario', {})
            duration = scenario.get('duration', 300)
            
            # Default benign traffic behaviors
            benign_traffic = [
                {
                    'name': 'normal_browsing',
                    'node': 'benign_user',
                    'script': '/scripts/benign.sh',
                    'script_args': ['--target', 'http://fancystore.com']
                },
                {
                    'name': 'login_and_shopping',
                    'node': 'benign_user',
                    'script': '/scripts/benign.sh',
                    'script_args': ['--target', 'http://fancystore.com']
                }
            ]
            
            # Only add default benign traffic if none is specified
            if not config['behaviors'].get('benign_traffic'):
                config['behaviors']['benign_traffic'] = benign_traffic
                
        except Exception as e:
            self.logger.warning(f"Failed to adapt benign behaviors: {e}")
        
        return config
    
    def _adapt_volume_paths(self, config: Dict) -> Dict:
        """Adapt volume paths to use relative paths"""
        try:
            project_root = self._get_project_root()
            
            for node in config.get('infrastructure', {}).get('nodes', []):
                if 'volumes' in node:
                    adapted_volumes = []
                    for volume in node['volumes']:
                        if isinstance(volume, str):
                            # Replace absolute paths with relative ones
                            if volume.startswith('/home/jiayi/SecurityLogs/CyberRange'):
                                volume = volume.replace('/home/jiayi/SecurityLogs/CyberRange', project_root)
                            adapted_volumes.append(volume)
                        else:
                            adapted_volumes.append(volume)
                    node['volumes'] = adapted_volumes
                    
        except Exception as e:
            self.logger.warning(f"Failed to adapt volume paths: {e}")
        
        return config
    
    def _validate_adapted_config(self, config: Dict) -> bool:
        """Validate adapted configuration"""
        required_sections = ['scenario', 'infrastructure', 'behaviors', 'data_collection']
        
        for section in required_sections:
            if section not in config:
                self.logger.error(f"Missing required section: {section}")
                return False
        
        # Validate scenario section
        scenario = config['scenario']
        if 'name' not in scenario:
            self.logger.error("Missing scenario name")
            return False
        
        # Validate infrastructure section
        infra = config['infrastructure']
        if 'nodes' not in infra:
            self.logger.error("Missing nodes in infrastructure")
            return False
        
        # Validate behaviors section
        behaviors = config['behaviors']
        if 'attacks' not in behaviors and 'benign_traffic' not in behaviors:
            self.logger.error("At least one of 'attacks' or 'benign_traffic' must be defined")
            return False
        
        # Validate data_collection section
        data_collection = config['data_collection']
        if 'logs' not in data_collection:
            self.logger.error("Missing logs in data_collection")
            return False
        
        self.logger.info("Configuration validation passed")
        return True
    
    def _deep_copy_dict(self, d: Dict) -> Dict:
        """Deep copy a dictionary"""
        import copy
        return copy.deepcopy(d)
    
    def _deep_merge_dicts(self, base: Dict, override: Dict) -> Dict:
        """
        Deep merge two dictionaries
        
        Args:
            base: Base dictionary
            override: Dictionary to merge into base
            
        Returns:
            Dict: Merged dictionary
        """
        import copy
        result = copy.deepcopy(base)
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge_dicts(result[key], value)
            else:
                result[key] = copy.deepcopy(value)
        
        return result


def load_config_with_adapter(config_path: str) -> Optional[Dict]:
    """
    Load configuration using the modular adapter
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Dict: Loaded and adapted configuration or None if failed
    """
    adapter = ConfigurationAdapter()
    return adapter.load_and_adapt_config(config_path)


def create_simple_config_template(output_path: str, scenario_name: str = "my-scenario"):
    """
    Create a simple configuration template
    
    Args:
        output_path: Path where to save the template
        scenario_name: Name of the scenario
    """
    simple_config = {
        'scenario': {
            'name': scenario_name,
            'description': f'Simple {scenario_name} configuration',
            'duration': 300,
            'random_seed': 12345,
            'attack_types': ['sql_injection', 'xss'],
            'waf_mode': 'off'
        }
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        yaml.dump(simple_config, f, default_flow_style=False, indent=2)
    
    print(f"Simple configuration template created: {output_path}")


if __name__ == "__main__":
    # Test the adapter
    adapter = ConfigurationAdapter()
    
    # Create a test configuration
    test_config = {
        'scenario': {
            'name': 'test-scenario',
            'attack_types': ['sql_injection'],
            'waf_mode': 'off'
        }
    }
    
    adapted = adapter._adapt_configuration(test_config)
    print("Adapted configuration:")
    import json
    print(json.dumps(adapted, indent=2))
