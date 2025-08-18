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
from .traffic_scheduler import create_parallel_behaviors, ParallelTrafficExecutor


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
    def __init__(self, config_path: str = "scenarios/config.yaml", config: Dict = None):
        """
        Initialize ScenarioManager
        
        Args:
            config_path: Path to scenario configuration file (used only if config is None)
            config: Pre-loaded configuration dictionary (takes precedence over config_path)
        """
        self.config_path = config_path
        
        # Setup logging first
        self.setup_logging()
        
        # Load configuration after logging is setup
        if config is not None:
            self.config = config
            self.logger.info(f"Using pre-loaded configuration: {config.get('scenario', {}).get('name', 'Unknown')}")
        else:
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
        """Create necessary output directories with timestamp"""
        import os
        from datetime import datetime
        
        # Create base directories
        os.makedirs('logs', exist_ok=True)
        os.makedirs('output', exist_ok=True)
        
        # Generate timestamp subfolder
        scenario_name = self.config.get('scenario', {}).get('name', 'unknown')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.experiment_dir = f"logs/{scenario_name}_{timestamp}"
        
        # Create experiment-specific directory structure
        experiment_subdirs = [
            self.experiment_dir,
            f"{self.experiment_dir}/nginx",
            f"{self.experiment_dir}/attacker", 
            f"{self.experiment_dir}/benign_user"
        ]
        
        # Add modsecurity directory only if WAF is enabled
        waf_mode = self.config.get('scenario', {}).get('waf_mode', 'off')
        if waf_mode == 'on':
            experiment_subdirs.append(f"{self.experiment_dir}/modsecurity")
        
        for directory in experiment_subdirs:
            os.makedirs(directory, exist_ok=True)
            # Set permissions for nginx/modsecurity directories to work with ModSecurity container
            if directory.endswith('/nginx') or directory.endswith('/modsecurity'):
                os.chmod(directory, 0o777)
                # Also ensure any existing files are writable
                for root, dirs, files in os.walk(directory):
                    for d in dirs:
                        os.chmod(os.path.join(root, d), 0o777)
                    for f in files:
                        os.chmod(os.path.join(root, f), 0o666)
            self.logger.info(f"Created experiment directory: {directory}")
        
        # Update log paths in configuration for this experiment
        self._update_log_paths_for_experiment()
    
    def _update_log_paths_for_experiment(self):
        """Update container volume paths to use experiment directory"""
        # Update nginx log volume
        if 'infrastructure' in self.config and 'nodes' in self.config['infrastructure']:
            for node in self.config['infrastructure']['nodes']:
                if node['name'] == 'nginx' and 'volumes' in node:
                    # Update nginx and modsecurity log volume paths
                    for i, volume in enumerate(node['volumes']):
                        if '/var/log/nginx' in volume:
                            host_path, container_path = volume.split(':', 1)
                            if host_path == './logs/nginx':
                                node['volumes'][i] = f"./{self.experiment_dir}/nginx:{container_path}"
                                self.logger.info(f"Updated nginx log path: {node['volumes'][i]}")
                        elif '/var/log/modsecurity' in volume:
                            host_path, container_path = volume.split(':', 1)
                            if host_path == './logs/modsecurity':
                                node['volumes'][i] = f"./{self.experiment_dir}/modsecurity:{container_path}"
                                self.logger.info(f"Updated modsecurity log path: {node['volumes'][i]}")
                
                elif node['name'] == 'attacker' and 'volumes' in node:
                    # Update attacker log volume path
                    for i, volume in enumerate(node['volumes']):
                        if '/logs' in volume and not '/scripts' in volume:
                            host_path, container_path = volume.split(':', 1)
                            if host_path == './logs/attacker':
                                node['volumes'][i] = f"./{self.experiment_dir}/attacker:{container_path}"
                                self.logger.info(f"Updated attacker log path: {node['volumes'][i]}")
                
                elif node['name'] == 'benign_user' and 'volumes' in node:
                    # Update benign user log volume path
                    for i, volume in enumerate(node['volumes']):
                        if '/logs' in volume and not '/scripts' in volume:
                            host_path, container_path = volume.split(':', 1)
                            if host_path == './logs/benign_user':
                                node['volumes'][i] = f"./{self.experiment_dir}/benign_user:{container_path}"
                                self.logger.info(f"Updated benign_user log path: {node['volumes'][i]}")
        
        # Update data collection paths
        if 'data_collection' in self.config and 'logs' in self.config['data_collection']:
            for log_config in self.config['data_collection']['logs']:
                if log_config['source'] == 'nginx':
                    log_config['path'] = f"/{self.experiment_dir}/nginx/detailed.log"
                elif log_config['source'] == 'modsecurity':
                    log_config['path'] = f"/{self.experiment_dir}/modsecurity/audit.log"
                elif log_config['source'] == 'attacker':
                    log_config['path'] = f"/{self.experiment_dir}/attacker/attack.log"
                elif log_config['source'] == 'benign_user':
                    log_config['path'] = f"/{self.experiment_dir}/benign_user/user.log"
        
        # Update network capture path
        if 'data_collection' in self.config and 'network' in self.config['data_collection']:
            for network_config in self.config['data_collection']['network']:
                if 'output' in network_config:
                    network_config['output'] = f"{self.experiment_dir}/network_traffic.pcap"
    
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
            
            # Phase 3: Execute realistic traffic schedule
            scenario_duration = self.config.get('scenario', {}).get('duration', 300)
            self.logger.info(f"Starting realistic traffic simulation for {scenario_duration} seconds")
            
            # Check if this is a percentage-based traffic configuration
            has_percentage_config = self._has_percentage_based_traffic()

            if has_percentage_config:
                self.logger.info("Using parallel traffic execution")
                success &= self.execute_parallel_traffic()
            else:
                self.logger.info("Using traditional behavior execution")
                # Start behaviors in background
                success &= self.execute_behaviors()

                # Wait for scenario duration while behaviors run
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
            self.logger.info(f"Found {len(nodes)} nodes to start")
            for node in nodes:
                self.logger.info(f"Starting container: {node['name']} ({node['image']})")
                container_info = self.container_manager.start_container(node)
                if container_info:
                    self.context.containers[node['name']] = container_info
                    self.logger.info(f"Successfully started container: {node['name']}")
                else:
                    self.logger.error(f"Failed to start container: {node['name']}")
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
    
    def _has_percentage_based_traffic(self) -> bool:
        """Check if configuration uses percentage-based traffic"""
        attacks = self.config.get('behaviors', {}).get('attacks', [])
        benign_traffic = self.config.get('behaviors', {}).get('benign_traffic', [])
        
        # Check if any behavior has percentage configuration
        for attack in attacks:
            if 'percentage' in attack:
                return True
        
        for benign in benign_traffic:
            if 'percentage' in benign:
                return True
                
        return False
    
    def execute_scheduled_traffic(self) -> bool:
        """Execute traffic based on percentage scheduling"""
        try:
            self.logger.info("Creating traffic schedule...")
            events = create_traffic_schedule(self.config)
            
            if not events:
                self.logger.warning("No traffic events scheduled")
                return True
            
            self.logger.info(f"Executing {len(events)} scheduled traffic events...")
            
            start_time = time.time()
            current_time = start_time
            
            for event in events:
                # Wait until it's time for this event
                wait_time = event.timestamp - current_time
                if wait_time > 0:
                    time.sleep(wait_time)
                
                current_time = time.time()
                
                # Execute the event
                try:
                    self.logger.debug(f"Executing {event.behavior_type} event: {event.behavior_name}")
                    
                    if event.behavior_type == 'attack':
                        attack_config = {
                            'name': event.behavior_name,
                            'node': event.node,
                            'script': event.script,
                            'script_args': event.script_args,
                            'payload_config': event.payload_config
                        }
                        self.execute_single_attack(attack_config)
                    else:  # benign traffic
                        benign_config = {
                            'name': event.behavior_name,
                            'node': event.node,
                            'script': event.script,
                            'script_args': event.script_args
                        }
                        self.execute_single_benign_traffic(benign_config)
                        
                except Exception as e:
                    self.logger.warning(f"Failed to execute event {event.behavior_name}: {str(e)}")
            
            self.logger.info("Scheduled traffic execution completed")
            return True
            
        except Exception as e:
            self.logger.error(f"Scheduled traffic execution failed: {str(e)}")
            return False
    
    def execute_single_attack(self, attack_config: Dict) -> bool:
        """Execute a single attack event"""
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
            
            # For scheduled attacks, we execute once without duration
            success = self.script_executor.execute_single_attack(
                container_id, script_path, payload_config, attack_config
            )
            
            return success
            
        except Exception as e:
            self.logger.error(f"Single attack execution failed: {str(e)}")
            return False
    
    def execute_single_benign_traffic(self, traffic_config: Dict) -> bool:
        """Execute a single benign traffic event"""
        try:
            node_name = traffic_config['node']
            script_path = traffic_config['script']
            
            # Add random seed to traffic config
            random_seed = self.config.get('scenario', {}).get('random_seed', 12345)
            traffic_config['random_seed'] = random_seed
            
            container_id = self.context.containers[node_name].id
            
            # For scheduled benign traffic, we execute once
            success = self.script_executor.execute_single_benign_traffic(
                container_id, script_path, traffic_config
            )
            
            return success
            
        except Exception as e:
            self.logger.error(f"Single benign traffic execution failed: {str(e)}")
            return False
    
    def execute_parallel_traffic(self) -> bool:
        """Execute traffic behaviors in parallel threads"""
        try:
            scenario_duration = self.config.get('scenario', {}).get('duration', 300)
            
            if scenario_duration == 0:
                self.logger.info("Executing unlimited parallel traffic (will stop when all behaviors complete)")
            else:
                self.logger.info(f"Executing parallel traffic for {scenario_duration} seconds")
            
            # Create parallel behaviors
            self.logger.info("Creating parallel traffic behaviors...")
            behaviors = create_parallel_behaviors(self.config)
            
            if not behaviors:
                self.logger.warning("No parallel behaviors created")
                return True
            
            # Create and start parallel executor
            executor = ParallelTrafficExecutor(scenario_duration)
            
            # Execute behaviors in parallel
            success = executor.execute_behaviors(
                behaviors=behaviors,
                attack_executor=self.execute_single_attack,
                benign_executor=self.execute_single_benign_traffic
            )
            
            if scenario_duration == 0:
                self.logger.info("Unlimited parallel traffic execution completed - all behaviors finished")
            else:
                self.logger.info("Parallel traffic execution completed")
            return success
            
        except Exception as e:
            self.logger.error(f"Parallel traffic execution failed: {str(e)}")
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
                
                # Add experiment directory to context
                context_data['EXPERIMENT_DIR'] = self.experiment_dir
                
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