#!/usr/bin/env python3
"""
Modular Configuration Parser
Converts simplified modular configuration to detailed orchestration format
"""

import yaml
import logging
from typing import Dict, List, Any
from pathlib import Path


class ModularConfigParser:
    """
    Parser for modular scenario configuration
    Converts user-friendly modular config to detailed orchestration format
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse_modular_config(self, config_path: str) -> Dict:
        """
        Parse modular configuration and convert to detailed format
        
        Args:
            config_path: Path to modular configuration file
            
        Returns:
            Dict: Detailed configuration for orchestration
        """
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                modular_config = yaml.safe_load(f)
            
            self.logger.info(f"Parsing modular configuration: {config_path}")
            
            # Convert to detailed format
            detailed_config = self._convert_to_detailed_format(modular_config)
            
            return detailed_config
            
        except Exception as e:
            self.logger.error(f"Failed to parse modular config {config_path}: {e}")
            raise
    
    def _convert_to_detailed_format(self, modular_config: Dict) -> Dict:
        """
        Convert modular configuration to detailed orchestration format
        """
        detailed_config = {
            'scenario': {
                'name': modular_config.get('name', 'modular_scenario'),
                'description': f"Modular scenario: {modular_config.get('name', 'modular_scenario')}",
                'duration': modular_config.get('timeout_seconds', 300),
                'random_seed': modular_config.get('random_seed', 42),
                'version': '1.0'
            },
            'infrastructure': {
                'networks': [],
                'nodes': []
            },
            'behaviors': {
                'attacks': [],
                'benign_traffic': []
            },
            'data_collection': {
                'logs': [],
                'network': [],
                'system': []
            },
            'hooks': {},
            'output': {
                'base_dir': 'output',
                'formats': ['csv'],
                'compression': False
            },
            'monitoring': {
                'metrics': [],
                'alerts': []
            }
        }
        
        # Convert nodes
        self._convert_nodes(modular_config, detailed_config)
        
        # Convert network
        self._convert_networks(modular_config, detailed_config)
        
        # Convert attackers
        self._convert_attackers(modular_config, detailed_config)
        
        # Convert users
        self._convert_users(modular_config, detailed_config)
        
        # Convert logs_to_collect
        self._convert_logs_to_collect(modular_config, detailed_config)
        
        # Convert hooks
        self._convert_hooks(modular_config, detailed_config)
        
        # Convert output and monitoring
        self._convert_output_and_monitoring(modular_config, detailed_config)
        
        return detailed_config
    
    def _convert_nodes(self, modular_config: Dict, detailed_config: Dict):
        """Convert nodes section"""
        if 'nodes' not in modular_config:
            return
        
        for node in modular_config['nodes']:
            detailed_node = {
                'name': node['id'],
                'role': self._determine_node_role(node['id']),
                'image': node['image']
            }
            
            # Add optional fields
            if 'env' in node:
                if isinstance(node['env'], dict):
                    detailed_node['environment'] = [f"{k}={v}" for k, v in node['env'].items()]
                elif isinstance(node['env'], list):
                    detailed_node['environment'] = node['env']
            
            if 'ports' in node:
                detailed_node['ports'] = node['ports']
            
            if 'volumes' in node:
                detailed_node['volumes'] = node['volumes']
            
            # Add to networks
            if 'networks' in node:
                detailed_node['networks'] = node['networks']
            elif 'network' in modular_config:
                # Legacy single network support
                network_name = modular_config['network']['name']
                detailed_node['networks'] = [network_name]
            
            detailed_config['infrastructure']['nodes'].append(detailed_node)
    
    def _convert_networks(self, modular_config: Dict, detailed_config: Dict):
        """Convert networks section"""
        if 'networks' not in modular_config:
            # Create default network
            detailed_config['infrastructure']['networks'].append({
                'name': 'default_network',
                'driver': 'bridge',
                'subnet': '172.21.0.0/16',
                'gateway': '172.21.0.1'
            })
            return
        
        networks = modular_config['networks']
        for network_name, network_config in networks.items():
            detailed_network = {
                'name': network_config['name'],
                'driver': network_config.get('driver', 'bridge')
            }
            
            if 'subnets' in network_config and network_config['subnets']:
                detailed_network['subnet'] = network_config['subnets'][0]
                detailed_network['gateway'] = self._get_gateway_from_subnet(network_config['subnets'][0])
            
            detailed_config['infrastructure']['networks'].append(detailed_network)
    
    def _convert_attackers(self, modular_config: Dict, detailed_config: Dict):
        """Convert attackers section"""
        if 'attackers' not in modular_config:
            return
        
        for attacker in modular_config['attackers']:
            detailed_attack = {
                'name': attacker['id'],
                'node': attacker['target'],
                'script': attacker['script']
            }
            
            # Convert trigger
            if 'trigger' in attacker:
                trigger = attacker['trigger']
                if trigger['type'] == 'at_start':
                    detailed_attack['trigger'] = {'type': 'immediate', 'value': 0}
                elif trigger['type'] == 'delay':
                    detailed_attack['trigger'] = {'type': 'delay', 'value': trigger['seconds']}
                elif trigger['type'] == 'after':
                    detailed_attack['trigger'] = {'type': 'delay', 'value': trigger['seconds']}
            
            # Add payload config
            if 'payload_config' in attacker:
                detailed_attack['payload_config'] = attacker['payload_config']
            
            # Add default values
            detailed_attack['interval'] = 2
            detailed_attack['duration'] = 60
            
            detailed_config['behaviors']['attacks'].append(detailed_attack)
    
    def _convert_users(self, modular_config: Dict, detailed_config: Dict):
        """Convert users section"""
        if 'users' not in modular_config:
            return
        
        for user in modular_config['users']:
            detailed_user = {
                'name': user['id'],
                'node': user['target'],
                'script': user['script']
            }
            
            # Convert trigger
            if 'trigger' in user:
                trigger = user['trigger']
                if trigger['type'] == 'schedule':
                    # Convert cron to delay for simplicity
                    detailed_user['trigger'] = {'type': 'delay', 'value': 10}
                elif trigger['type'] == 'after':
                    detailed_user['trigger'] = {'type': 'delay', 'value': trigger['seconds']}
            
            # Add default values
            detailed_user['duration'] = 300
            detailed_user['interval'] = 5
            
            detailed_config['behaviors']['benign_traffic'].append(detailed_user)
    
    def _convert_logs_to_collect(self, modular_config: Dict, detailed_config: Dict):
        """Convert logs_to_collect section"""
        if 'logs_to_collect' not in modular_config:
            return
        
        for log_config in modular_config['logs_to_collect']:
            detailed_log = {
                'source': log_config['container'],
                'path': log_config['path'],
                'real_time': True
            }
            
            if 'parser' in log_config:
                detailed_log['parser'] = log_config['parser']
            
            if 'output' in log_config:
                detailed_log['output'] = log_config['output']
            
            detailed_config['data_collection']['logs'].append(detailed_log)
    
    def _convert_hooks(self, modular_config: Dict, detailed_config: Dict):
        """Convert hooks section"""
        if 'hooks' not in modular_config:
            return
        
        hooks = modular_config['hooks']
        
        # Convert after_logs_collected
        if 'after_logs_collected' in hooks:
            detailed_config['hooks']['post_collection'] = []
            for hook in hooks['after_logs_collected']:
                if isinstance(hook, str):
                    detailed_config['hooks']['post_collection'].append({
                        'name': f"hook_{len(detailed_config['hooks']['post_collection'])}",
                        'script': hook,
                        'timeout': 60
                    })
                elif isinstance(hook, dict):
                    detailed_config['hooks']['post_collection'].append({
                        'name': hook.get('name', f"hook_{len(detailed_config['hooks']['post_collection'])}"),
                        'script': hook['script'],
                        'context': hook.get('context', []),
                        'timeout': hook.get('timeout', 60)
                    })
        
        # Convert after_start
        if 'after_start' in hooks:
            detailed_config['hooks']['post_node_start'] = []
            for hook in hooks['after_start']:
                if isinstance(hook, str):
                    detailed_config['hooks']['post_node_start'].append({
                        'name': f"verify_{len(detailed_config['hooks']['post_node_start'])}",
                        'script': hook,
                        'timeout': 30
                    })
                elif isinstance(hook, dict):
                    detailed_config['hooks']['post_node_start'].append({
                        'name': hook.get('name', f"verify_{len(detailed_config['hooks']['post_node_start'])}"),
                        'script': hook['script'],
                        'context': hook.get('context', []),
                        'timeout': hook.get('timeout', 30)
                    })
    
    def _convert_output_and_monitoring(self, modular_config: Dict, detailed_config: Dict):
        """Convert output and monitoring sections"""
        # Output
        if 'output' in modular_config:
            detailed_config['output'].update(modular_config['output'])
        
        # Monitoring
        if 'monitoring' in modular_config:
            detailed_config['monitoring'].update(modular_config['monitoring'])
    
    def _determine_node_role(self, node_id: str) -> str:
        """Determine node role based on ID"""
        if 'attacker' in node_id.lower():
            return 'attacker'
        elif 'user' in node_id.lower() or 'benign' in node_id.lower():
            return 'user'
        elif 'proxy' in node_id.lower() or 'nginx' in node_id.lower():
            return 'proxy'
        else:
            return 'target'
    
    def _get_gateway_from_subnet(self, subnet: str) -> str:
        """Get gateway IP from subnet"""
        # Simple implementation: take first IP in subnet
        parts = subnet.split('/')[0].split('.')
        parts[-1] = '1'
        return '.'.join(parts)
    
    def save_detailed_config(self, detailed_config: Dict, output_path: str):
        """Save detailed configuration to file"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                yaml.dump(detailed_config, f, default_flow_style=False, indent=2)
            
            self.logger.info(f"Saved detailed configuration to: {output_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save detailed config: {e}")
            raise


def main():
    """Test the modular config parser"""
    print("🚀 CyberRange Modular Config Parser Test")
    print("=" * 50)
    
    # Test modular config parser
    print("\nTesting Modular Config Parser...")
    parser = ModularConfigParser()
    
    try:
        # Parse modular config
        modular_config = parser.parse_modular_config("scenarios/modular_demo.yaml")
        
        # Save detailed config
        parser.save_detailed_config(modular_config, "scenarios/modular_demo_detailed.yaml")
        
        print("✅ Modular configuration parsed successfully!")
        print(f"   - Scenario: {modular_config['scenario']['name']}")
        print(f"   - Nodes: {len(modular_config['infrastructure']['nodes'])}")
        print(f"   - Attacks: {len(modular_config['behaviors']['attacks'])}")
        print(f"   - Users: {len(modular_config['behaviors']['benign_traffic'])}")
        print(f"   - Log sources: {len(modular_config['data_collection']['logs'])}")
        
        print("\n" + "=" * 50)
        print("✅ Config parser test completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Modular config parser failed: {e}")
        return False


if __name__ == "__main__":
    main() 