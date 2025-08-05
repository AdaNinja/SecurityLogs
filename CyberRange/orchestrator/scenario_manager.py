#!/usr/bin/env python3
"""
Scenario Manager for CyberRange
Manages the complete lifecycle of attack simulation scenarios
"""

import os
import yaml
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass

from .container_manager import ContainerManager
from .script_executor import ScriptExecutor
from .log_collector import LogCollector
from .error_handler import ErrorHandler


@dataclass
class ScenarioContext:
    """Context information for scenario execution"""
    scenario_name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str = "initialized"
    containers: Dict = None
    log_files: Dict = None
    errors: List = None
    
    def __post_init__(self):
        if self.containers is None:
            self.containers = {}
        if self.log_files is None:
            self.log_files = {}
        if self.errors is None:
            self.errors = []


class ScenarioManager:
    def __init__(self, config_path: str = "scenarios/config.yaml"):
        """
        Initialize ScenarioManager
        
        Args:
            config_path: Path to scenario configuration file
        """
        self.config_path = config_path
        
        # Setup logging first
        self.setup_logging()
        
        # Load configuration after logging is setup
        self.config = self.load_config()
        self.context = None
        
        # Create output directories
        self._create_output_directories()
        
        # Initialize components
        self.container_manager = ContainerManager()
        self.script_executor = ScriptExecutor()
        self.log_collector = LogCollector()
        self.error_handler = ErrorHandler()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('scenario.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _create_output_directories(self):
        """Create necessary output directories"""
        import os
        
        # Create base directories
        directories = [
            'logs',
            'output'
        ]
        
        # Create subdirectories for logs
        log_subdirs = [
            'logs/nginx',
            'logs/attacker',
            'logs/benign_user'
        ]
        
        for directory in directories + log_subdirs:
            if not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
                self.logger.info(f"Created directory: {directory}")
    
    def load_config(self) -> Dict:
        """Load scenario configuration from YAML file"""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        self.logger.info(f"Loaded configuration: {config.get('scenario', {}).get('name', 'Unknown')}")
        return config
    
    def run_scenario(self) -> bool:
        """
        Run the complete scenario
        
        Returns:
            bool: True if scenario completed successfully, False otherwise
        """
        try:
            self.logger.info("Starting scenario execution")
            
            # Set random seed for reproducibility
            random_seed = self.config.get('scenario', {}).get('random_seed', 12345)
            import random
            random.seed(random_seed)
            self.logger.info(f"Set random seed: {random_seed}")
            
            # Initialize context
            self.context = ScenarioContext(
                scenario_name=self.config['scenario']['name'],
                start_time=datetime.now()
            )
            
            # Execute scenario phases
            success = True
            
            # Phase 1: Pre-scenario hooks
            success &= self.execute_hooks('pre_scenario')
            
            # Phase 2: Start infrastructure
            success &= self.start_infrastructure()
            
            # Phase 3: Execute behaviors
            success &= self.execute_behaviors()
            
            # Phase 3.5: Wait for scenario duration
            scenario_duration = self.config.get('scenario', {}).get('duration', 300)
            self.logger.info(f"Waiting for scenario duration: {scenario_duration} seconds")
            time.sleep(scenario_duration)
            
            # Phase 4: Collect data
            success &= self.collect_data()
            
            # Phase 5: Post-collection hooks (parse logs to CSV)
            success &= self.execute_hooks('post_collection')
            
            # Phase 6: Post-scenario hooks
            success &= self.execute_hooks('post_scenario')
            
            # Update context
            self.context.end_time = datetime.now()
            self.context.status = "completed" if success else "failed"
            
            self.logger.info(f"Scenario completed with status: {self.context.status}")
            return success
            
        except Exception as e:
            self.logger.error(f"Scenario execution failed: {str(e)}")
            if self.context:
                self.context.status = "failed"
                self.context.errors.append(str(e))
            return False
    
    def start_infrastructure(self) -> bool:
        """Start infrastructure components (networks, containers)"""
        try:
            self.logger.info("Starting infrastructure")
            
            # Create networks
            networks = self.config.get('infrastructure', {}).get('networks', [])
            for network in networks:
                self.container_manager.create_network(network)
            
            # Start containers
            nodes = self.config.get('infrastructure', {}).get('nodes', [])
            for node in nodes:
                container_info = self.container_manager.start_container(node)
                if container_info:
                    self.context.containers[node['name']] = container_info
                else:
                    raise Exception(f"Failed to start container: {node['name']}")
            
            # Start network capture early
            network_configs = self.config.get('data_collection', {}).get('network', [])
            for network_config in network_configs:
                pcap_file = self.log_collector.capture_network(network_config, self.context)
                if pcap_file:
                    self.context.log_files['network'] = pcap_file
            
            # Wait for services to be ready
            self.wait_for_services()
            
            # Execute post-node-start hooks
            self.execute_hooks('post_node_start')
            
            self.logger.info("Infrastructure started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Infrastructure startup failed: {str(e)}")
            return False
    
    def execute_behaviors(self) -> bool:
        """Execute attack and benign behaviors"""
        try:
            self.logger.info("Executing behaviors")
            
            # Execute attacks
            attacks = self.config.get('behaviors', {}).get('attacks', [])
            for attack in attacks:
                success = self.execute_attack(attack)
                if not success:
                    self.logger.warning(f"Attack {attack['name']} failed")
            
            # Execute benign traffic
            benign_traffic = self.config.get('behaviors', {}).get('benign_traffic', [])
            for traffic in benign_traffic:
                success = self.execute_benign_traffic(traffic)
                if not success:
                    self.logger.warning(f"Benign traffic {traffic['name']} failed")
            
            self.logger.info("Behaviors executed")
            return True
            
        except Exception as e:
            self.logger.error(f"Behavior execution failed: {str(e)}")
            return False
    
    def execute_attack(self, attack_config: Dict) -> bool:
        """Execute a single attack"""
        try:
            node_name = attack_config['node']
            script_path = attack_config['script']
            
            # Get payload configuration
            payload_config = attack_config.get('payload_config', {})
            
            # Add random seed to attack config
            random_seed = self.config.get('scenario', {}).get('random_seed', 12345)
            attack_config['random_seed'] = random_seed
            
            # Execute attack script with payload configuration
            container_id = self.context.containers[node_name].id
            success = self.script_executor.execute_attack(
                container_id, script_path, payload_config, attack_config
            )
            
            if success:
                # Execute post-attack hooks
                self.execute_hooks('post_attack', {'attack_info': attack_config})
            
            return success
            
        except Exception as e:
            self.logger.error(f"Attack execution failed: {str(e)}")
            return False
    
    def execute_benign_traffic(self, traffic_config: Dict) -> bool:
        """Execute benign traffic generation"""
        try:
            node_name = traffic_config['node']
            script_path = traffic_config['script']
            
            # Add random seed to traffic config
            random_seed = self.config.get('scenario', {}).get('random_seed', 12345)
            traffic_config['random_seed'] = random_seed
            
            container_id = self.context.containers[node_name].id
            success = self.script_executor.execute_benign_traffic(
                container_id, script_path, traffic_config
            )
            
            return success
            
        except Exception as e:
            self.logger.error(f"Benign traffic execution failed: {str(e)}")
            return False
    
    def get_payloads(self, payload_config: Dict) -> List[str]:
        """Get payloads based on configuration"""
        try:
            from attacks.payload_manager import PayloadManager
            
            payload_mgr = PayloadManager()
            files = payload_config.get('files', [])
            lines = payload_config.get('lines')
            
            if files:
                return payload_mgr.get_payloads(files, lines)
            else:
                return []
                
        except Exception as e:
            self.logger.error(f"Failed to get payloads: {str(e)}")
            return []
    
    def collect_data(self) -> bool:
        """Collect logs and data from all sources"""
        try:
            self.logger.info("Collecting data")
            
            # Collect logs
            log_configs = self.config.get('data_collection', {}).get('logs', [])
            for log_config in log_configs:
                log_file = self.log_collector.collect_log(log_config, self.context)
                if log_file:
                    self.context.log_files[log_config['source']] = log_file
            
            # Network capture is already started in start_infrastructure()
            # Just ensure the pcap file exists
            if 'network' in self.context.log_files:
                pcap_file = self.context.log_files['network']
                if not os.path.exists(pcap_file):
                    self.logger.warning(f"Network capture file not found: {pcap_file}")
            
            # Execute post-collection hooks
            self.execute_hooks('post_collection')
            
            self.logger.info("Data collection completed")
            return True
            
        except Exception as e:
            self.logger.error(f"Data collection failed: {str(e)}")
            return False
    
    def execute_hooks(self, hook_type: str, context: Dict = None) -> bool:
        """Execute hooks of specified type"""
        try:
            hooks = self.config.get('hooks', {}).get(hook_type, [])
            
            for hook in hooks:
                hook_name = hook['name']
                script_path = hook['script']
                hook_context = hook.get('context', [])
                timeout = hook.get('timeout', 60)
                
                # Prepare context data
                context_data = self.prepare_hook_context(hook_context, context)
                
                # Execute hook
                success = self.script_executor.execute_hook(
                    script_path, context_data, timeout
                )
                
                if not success:
                    self.logger.warning(f"Hook {hook_name} failed")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Hook execution failed: {str(e)}")
            return False
    
    def prepare_hook_context(self, hook_context: List, additional_context: Dict = None) -> Dict:
        """Prepare context data for hook execution"""
        context_data = {}
        
        if additional_context:
            context_data.update(additional_context)
        
        # Add scenario context
        if self.context:
            # Convert ContainerInfo objects to dictionaries for JSON serialization
            containers_data = {}
            for name, container_info in self.context.containers.items():
                containers_data[name] = {
                    'id': container_info.id,
                    'name': container_info.name,
                    'status': container_info.status,
                    'ip_address': container_info.ip_address,
                    'ports': container_info.ports,
                    'networks': container_info.networks
                }
            
            context_data.update({
                'scenario_name': self.context.scenario_name,
                'start_time': self.context.start_time.isoformat(),
                'containers': containers_data,
                'log_files': self.context.log_files,
                'errors': self.context.errors
            })
        
        return context_data
    
    def wait_for_services(self, timeout: int = 300):
        """Wait for services to be ready"""
        self.logger.info("Waiting for services to be ready")
        time.sleep(10)  # Basic wait, can be enhanced with health checks
    
    def cleanup(self):
        """Cleanup resources after scenario execution"""
        try:
            self.logger.info("Cleaning up resources")
            
            # Stop containers first
            for container_name, container_info in self.context.containers.items():
                self.container_manager.stop_container(container_info.id)
            
            # Wait a moment for tcpdump to finish writing
            import time
            time.sleep(2)
            
            # Stop tcpdump if running
            if hasattr(self.context, 'tcpdump_pid') and self.context.tcpdump_pid:
                try:
                    import subprocess
                    subprocess.run(['sudo', 'kill', str(self.context.tcpdump_pid)], 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.logger.info(f"Stopped tcpdump process (PID: {self.context.tcpdump_pid})")
                except Exception as e:
                    self.logger.warning(f"Failed to stop tcpdump: {e}")
            
            # Also kill any remaining tcpdump processes
            try:
                import subprocess
                subprocess.run(['sudo', 'pkill', '-f', 'tcpdump'], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
            
            # Remove networks
            networks = self.config.get('infrastructure', {}).get('networks', [])
            for network in networks:
                self.container_manager.remove_network(network['name'])
            
            self.logger.info("Cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Cleanup failed: {str(e)}")
    
    def get_scenario_summary(self) -> Dict:
        """Get scenario execution summary"""
        if not self.context:
            return {}
        
        duration = None
        if self.context.end_time:
            duration = (self.context.end_time - self.context.start_time).total_seconds()
        
        return {
            'scenario_name': self.context.scenario_name,
            'status': self.context.status,
            'start_time': self.context.start_time.isoformat(),
            'end_time': self.context.end_time.isoformat() if self.context.end_time else None,
            'duration_seconds': duration,
            'containers_started': len(self.context.containers),
            'log_files_collected': len(self.context.log_files),
            'errors': self.context.errors
        }


def main():
    """Test the ScenarioManager"""
    manager = ScenarioManager()
    
    try:
        success = manager.run_scenario()
        summary = manager.get_scenario_summary()
        
        print("Scenario Summary:")
        for key, value in summary.items():
            print(f"  {key}: {value}")
        
        if success:
            print("Scenario completed successfully!")
        else:
            print("Scenario failed!")
            
    finally:
        manager.cleanup()


if __name__ == "__main__":
    main() 