#!/usr/bin/env python3
"""
Script Executor for CyberRange
Executes scripts in containers for attacks and benign traffic
"""

import docker
import logging
import time
import json
import subprocess
from typing import Dict, List, Optional
import os


class ScriptExecutor:
    def __init__(self):
        """Initialize ScriptExecutor"""
        try:
            self.client = docker.from_env()
            self.logger = logging.getLogger(__name__)
        except Exception as e:
            self.logger.error(f"Failed to initialize Docker client: {str(e)}")
            raise
    
    def execute_attack(self, container_id: str, script_path: str, payload_config: Dict, attack_config: Dict) -> bool:
        """
        Execute attack script in container
        
        Args:
            container_id: Container ID
            script_path: Path to attack script in container
            payload_config: Payload configuration with files and lines
            attack_config: Attack configuration
            
        Returns:
            bool: True if attack executed successfully
        """
        try:
            container = self.client.containers.get(container_id)
            
            # Prepare attack command
            interval = attack_config.get('interval', 2)
            # Use attack-specific duration if provided, otherwise use a reasonable default for attacks
            duration = attack_config.get('duration', 20)  # Default 20 seconds for individual attacks
            
            # Get target URL from container environment
            target_url = self._get_target_url(container)
            
            # Prepare attack script parameters
            script_params = []
            
            # Add target URL
            if target_url:
                script_params.extend(["--target", target_url])
            
            # Add attack file if specified
            if payload_config and 'files' in payload_config:
                attack_file = payload_config['files'][0]  # Use first file
                script_params.extend(["--attack-file", attack_file])
            
            # Add line range if specified
            if payload_config and 'lines' in payload_config:
                lines = payload_config['lines']
                if lines == "all":
                    # Don't add --start/--end for "all" - let script execute all payloads
                    pass
                elif isinstance(lines, list) and len(lines) >= 2:
                    start_line = lines[0]
                    end_line = lines[1]
                    script_params.extend(["--start", str(start_line), "--end", str(end_line)])
                elif isinstance(lines, list) and len(lines) == 1:
                    # Single line - execute just that one
                    script_params.extend(["--start", str(lines[0]), "--end", str(lines[0])])
            
            # Add duration parameter if available
            if duration > 0:
                script_params.extend(["--duration", str(duration)])
            
            # New: Add script arguments (attack type, WAF mode, etc.)
            if 'script_args' in attack_config:
                script_params.extend(attack_config['script_args'])
            
            # Build command
            command = f"bash {script_path} {' '.join(script_params)}"
            
            self.logger.info(f"Attack command: {command}")
            

            
            # Execute attack script in background
            exec_result = container.exec_run(
                command,
                detach=True,
                tty=True,
                environment={
                    'TARGET_URL': target_url,
                    'ATTACK_PHASE': 'automated',
                    'RANDOM_SEED': str(attack_config.get('random_seed', 12345))
                }
            )
            
            self.logger.info(f"Started attack in container {container_id} with exec_id: {exec_result}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to execute attack in container {container_id}: {str(e)}")
            return False
    
    def execute_single_attack(self, container_id: str, script_path: str, payload_config: Dict, attack_config: Dict) -> bool:
        """
        Execute a single attack without duration (for scheduled attacks)
        
        Args:
            container_id: Container ID
            script_path: Path to attack script in container
            payload_config: Payload configuration with files and lines
            attack_config: Attack configuration
            
        Returns:
            bool: True if attack executed successfully
        """
        try:
            container = self.client.containers.get(container_id)
            
            # Get target URL from container environment
            target_url = self._get_target_url(container)
            
            # Prepare attack script parameters for single execution
            script_params = []
            
            # Add target URL
            if target_url:
                script_params.extend(["--target", target_url])
            
            # Add attack file if specified
            if payload_config and 'files' in payload_config:
                attack_file = payload_config['files'][0]  # Use first file
                script_params.extend(["--attack-file", attack_file])
            
            # Add line range if specified
            if payload_config and 'lines' in payload_config:
                start_line = payload_config['lines'][0]
                end_line = payload_config['lines'][1]
                script_params.extend(["--start", str(start_line), "--end", str(end_line)])
            
            # For single attacks, don't add duration (execute once)
            
            # Add script arguments (attack type, WAF mode, etc.)
            if 'script_args' in attack_config:
                script_params.extend(attack_config['script_args'])
            
            # Build command
            command = f"bash {script_path} {' '.join(script_params)}"
            
            self.logger.debug(f"Single attack command: {command}")
            
            # Execute attack script once (not in background)
            exec_result = container.exec_run(
                command,
                detach=False,  # Wait for completion
                tty=False,
                environment={
                    'TARGET_URL': target_url,
                    'ATTACK_PHASE': 'scheduled',
                    'RANDOM_SEED': str(attack_config.get('random_seed', 12345))
                }
            )
            
            if exec_result.exit_code == 0:
                self.logger.debug(f"Single attack completed successfully in container {container_id}")
                return True
            else:
                self.logger.warning(f"Single attack failed in container {container_id} with exit code {exec_result.exit_code}")
                return False
            
        except Exception as e:
            self.logger.error(f"Single attack execution failed: {str(e)}")
            return False
    
    def execute_single_benign_traffic(self, container_id: str, script_path: str, traffic_config: Dict) -> bool:
        """
        Execute a single benign traffic event (for scheduled traffic)
        
        Args:
            container_id: Container ID
            script_path: Path to benign script in container
            traffic_config: Traffic configuration
            
        Returns:
            bool: True if traffic executed successfully
        """
        try:
            container = self.client.containers.get(container_id)
            
            # Get target URL from container environment
            target_url = self._get_target_url(container)
            
            # Prepare traffic script parameters for single execution
            script_params = []
            
            # Add script arguments (which already include --target from YAML)
            if 'script_args' in traffic_config:
                script_params.extend(traffic_config['script_args'])
            else:
                # Fallback: Add target URL if no script args provided
                if target_url:
                    script_params.extend(["--target", target_url])
            
            # Build command
            command = f"bash {script_path} {' '.join(script_params)}"
            
            self.logger.debug(f"Single benign traffic command: {command}")
            
            # Execute benign traffic script once
            exec_result = container.exec_run(
                command,
                detach=False,  # Wait for completion
                tty=False,
                environment={
                    'TARGET_URL': target_url,
                    'USER_PHASE': 'scheduled',
                    'RANDOM_SEED': str(traffic_config.get('random_seed', 12345))
                }
            )
            
            if exec_result.exit_code == 0:
                self.logger.debug(f"Single benign traffic completed successfully in container {container_id}")
                return True
            else:
                self.logger.warning(f"Single benign traffic failed in container {container_id} with exit code {exec_result.exit_code}")
                return False
            
        except Exception as e:
            self.logger.error(f"Single benign traffic execution failed: {str(e)}")
            return False
    
    def execute_benign_traffic(self, container_id: str, script_path: str, traffic_config: Dict) -> bool:
        """
        Execute benign traffic script in container
        
        Args:
            container_id: Container ID
            script_path: Path to benign script in container
            traffic_config: Traffic configuration
            
        Returns:
            bool: True if traffic generation executed successfully
        """
        try:
            container = self.client.containers.get(container_id)
            
            # Prepare traffic command
            interval = traffic_config.get('interval', 2)
            duration = traffic_config.get('duration', 300)
            
            # Get target URL from container environment
            target_url = self._get_target_url(container)
            
            # Get script arguments if provided
            script_args = traffic_config.get('script_args', [])
            args_str = ' '.join(script_args) if script_args else ''
            
            # Execute benign script with proper parameters
            command = f"bash {script_path} {args_str}".strip()
            
            self.logger.info(f"Benign traffic command: {command}")
            

            
            # Execute in background
            exec_result = container.exec_run(
                command,
                detach=True,
                tty=True,
                environment={
                    'TARGET_URL': target_url,
                    'USER_TYPE': 'normal',
                    'RANDOM_SEED': str(traffic_config.get('random_seed', 12345))
                }
            )
            
            self.logger.info(f"Started benign traffic in container {container_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to execute benign traffic in container {container_id}: {str(e)}")
            return False
    
    def execute_hook(self, script_path: str, context_data: Dict, timeout: int = 60) -> bool:
        """
        Execute hook script
        
        Args:
            script_path: Path to hook script
            context_data: Context data to pass to hook
            timeout: Execution timeout in seconds
            
        Returns:
            bool: True if hook executed successfully
        """
        try:
            # Check if script exists
            if not script_path.startswith('/'):
                script_path = f"./{script_path}"
            
            if not os.path.exists(script_path):
                self.logger.warning(f"Hook script not found: {script_path}")
                return False
            
            # Prepare context data as environment variables
            env = os.environ.copy()
            
            # Convert ContainerInfo objects to dictionaries for JSON serialization
            containers_data = {}
            if 'containers' in context_data:
                for name, container_info in context_data['containers'].items():
                    # Handle both ContainerInfo objects and dictionaries
                    if hasattr(container_info, 'id'):
                        # ContainerInfo object
                        containers_data[name] = {
                            'id': container_info.id,
                            'name': container_info.name,
                            'status': container_info.status,
                            'ip_address': container_info.ip_address,
                            'ports': container_info.ports,
                            'networks': container_info.networks
                        }
                    elif isinstance(container_info, dict):
                        # Already a dictionary
                        containers_data[name] = container_info
                    else:
                        # Unknown type, try to convert to string
                        containers_data[name] = {'id': str(container_info)}
            
            env.update({
                'CYBERRANGE_CONTEXT': json.dumps(context_data),
                'SCENARIO_NAME': context_data.get('scenario_name', ''),
                'START_TIME': context_data.get('start_time', ''),
                'CONTAINERS': json.dumps(containers_data),
                'LOG_FILES': json.dumps(context_data.get('log_files', {})),
                'scenario_name': context_data.get('scenario_name', ''),
                'duration': str(context_data.get('duration', 300)),
                'EXPERIMENT_DIR': context_data.get('EXPERIMENT_DIR', 'logs')
            })
            
            # Execute hook script
            if script_path.endswith('.py'):
                # Python script
                result = subprocess.run(
                    ['python3', script_path],
                    env=env,
                    timeout=timeout,
                    capture_output=True,
                    text=True
                )
            else:
                # Shell script
                result = subprocess.run(
                    ['bash', script_path],
                    env=env,
                    timeout=timeout,
                    capture_output=True,
                    text=True
                )
            
            if result.returncode == 0:
                self.logger.info(f"Hook executed successfully: {script_path}")
                return True
            else:
                self.logger.error(f"Hook failed: {script_path}, return code: {result.returncode}")
                self.logger.error(f"Error output: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Hook timeout: {script_path}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to execute hook {script_path}: {str(e)}")
            return False
    
    def execute_command_in_container(self, container_id: str, command: str, timeout: int = 30) -> Dict:
        """
        Execute command in container
        
        Args:
            container_id: Container ID
            command: Command to execute
            timeout: Execution timeout in seconds
            
        Returns:
            Dict: Command execution result
        """
        try:
            container = self.client.containers.get(container_id)
            
            exec_result = container.exec_run(
                command,
                timeout=timeout
            )
            
            return {
                'exit_code': exec_result.exit_code,
                'output': exec_result.output.decode('utf-8'),
                'success': exec_result.exit_code == 0
            }
            
        except Exception as e:
            self.logger.error(f"Failed to execute command in container {container_id}: {str(e)}")
            return {
                'exit_code': -1,
                'output': str(e),
                'success': False
            }
    
    def wait_for_script_completion(self, container_id: str, script_name: str, timeout: int = 300) -> bool:
        """
        Wait for script to complete execution
        
        Args:
            container_id: Container ID
            script_name: Name of the script to wait for
            timeout: Timeout in seconds
            
        Returns:
            bool: True if script completed successfully
        """
        try:
            container = self.client.containers.get(container_id)
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                # Check if script process is still running
                result = self.execute_command_in_container(
                    container_id,
                    f"pgrep -f {script_name}"
                )
                
                if not result['success']:
                    # Process not found, script completed
                    self.logger.info(f"Script {script_name} completed in container {container_id}")
                    return True
                
                time.sleep(5)
            
            self.logger.warning(f"Script {script_name} did not complete within {timeout} seconds")
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to wait for script completion: {str(e)}")
            return False
    
    def _get_target_url(self, container) -> str:
        """
        Get target URL from container environment
        
        Args:
            container: Docker container object
            
        Returns:
            str: Target URL
        """
        try:
            # Get environment variables
            env_vars = container.attrs['Config']['Env']
            
            # Look for TARGET_URL
            for env_var in env_vars:
                if env_var.startswith('TARGET_URL='):
                    return env_var.split('=', 1)[1]
            
            # Fallback to TARGET_HOST and TARGET_PORT
            target_host = None
            target_port = None
            
            for env_var in env_vars:
                if env_var.startswith('TARGET_HOST='):
                    target_host = env_var.split('=', 1)[1]
                elif env_var.startswith('TARGET_PORT='):
                    target_port = env_var.split('=', 1)[1]
            
            if target_host:
                if target_port and target_port != '80':
                    return f"http://{target_host}:{target_port}"
                else:
                    return f"http://{target_host}"
            
            return "http://juice_shop:3000"  # Default fallback
            
        except Exception as e:
            self.logger.warning(f"Failed to get target URL from container: {e}")
            return "http://juice_shop:3000"  # Default fallback
    
    def get_script_logs(self, container_id: str, log_path: str) -> str:
        """
        Get script execution logs from container
        
        Args:
            container_id: Container ID
            log_path: Path to log file in container
            
        Returns:
            str: Log content
        """
        try:
            container = self.client.containers.get(container_id)
            
            # Read log file
            result = container.exec_run(f"cat {log_path}")
            
            if result.exit_code == 0:
                return result.output.decode('utf-8')
            else:
                self.logger.warning(f"Failed to read log file {log_path} from container {container_id}")
                return ""
                
        except Exception as e:
            self.logger.error(f"Failed to get script logs: {str(e)}")
            return ""


def main():
    """Test the ScriptExecutor"""
    executor = ScriptExecutor()
    
    # List containers
    containers = executor.client.containers.list()
    print("Available containers:")
    for container in containers:
        print(f"  {container.name}: {container.id}")
    
    if containers:
        # Test command execution
        test_container = containers[0]
        result = executor.execute_command_in_container(
            test_container.id,
            "echo 'Hello from container'"
        )
        print(f"\nTest command result: {result}")


if __name__ == "__main__":
    main() 