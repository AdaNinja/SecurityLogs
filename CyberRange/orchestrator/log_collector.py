#!/usr/bin/env python3
"""
Log Collector for CyberRange
Collects logs from containers and host system
"""

import os
import shutil
import logging
import subprocess
import time
import signal
from datetime import datetime
from typing import Dict, Optional
import docker
import sys

# Add parsers to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'parsers'))


class LogCollector:
    def __init__(self):
        """Initialize LogCollector"""
        try:
            self.client = docker.from_env()
            self.logger = logging.getLogger(__name__)
        except Exception as e:
            self.logger.error(f"Failed to initialize Docker client: {str(e)}")
            raise
    
    def collect_log(self, log_config: Dict, context) -> Optional[str]:
        """
        Collect log file from container or host
        
        Args:
            log_config: Log configuration
            context: Scenario context
            
        Returns:
            str: Path to collected log file or None if failed
        """
        try:
            source = log_config['source']
            container_path = log_config['path']
            
            # Use original log filename, not CSV filename
            log_filename = os.path.basename(container_path)
            
            # For container logs, use the volume-mounted path directly
            if source != 'host':
                # Map container paths to host paths based on volume mounts
                path_mapping = {
                    'nginx': {
                        '/var/log/nginx/detailed.log': 'logs/nginx/detailed.log',
                        '/var/log/nginx/access.log': 'logs/nginx/access.log',
                        '/var/log/nginx/error.log': 'logs/nginx/error.log'
                    },
                    'attacker': {
                        '/logs/attack.log': 'logs/attacker/attack.log'
                    },
                    'benign_user': {
                        '/logs/user.log': 'logs/benign_user/user.log'
                    }
                }
                
                # Get the host path for this container and log file
                if source in path_mapping and container_path in path_mapping[source]:
                    host_path = path_mapping[source][container_path]
                    
                    # Check if the file exists
                    if os.path.exists(host_path):
                        self.logger.info(f"Using volume-mounted log: {host_path}")
                        return host_path
                    else:
                        self.logger.warning(f"Volume-mounted log not found: {host_path}")
                        return None
                else:
                    self.logger.warning(f"No path mapping found for {source}:{container_path}")
                    return None
            
            # For host logs, collect normally
            else:
                # Create output directory in logs folder with source subdirectory
                output_dir = os.path.join("logs", source)
                os.makedirs(output_dir, exist_ok=True)
                
                output_path = os.path.join(output_dir, log_filename)
                
                if os.path.exists(container_path):
                    shutil.copy2(container_path, output_path)
                    self.logger.info(f"Collected host log: {container_path} -> {output_path}")
                    return output_path
                else:
                    self.logger.warning(f"Host log file not found: {container_path}")
                    return None
            
        except Exception as e:
            self.logger.error(f"Failed to collect log: {str(e)}")
            return None
    
    def capture_network(self, network_config: Dict, context) -> Optional[str]:
        """
        Capture network traffic using tcpdump
        
        Args:
            network_config: Network capture configuration
            context: Scenario context
            
        Returns:
            str: Path to captured pcap file or None if failed
        """
        try:
            interface = network_config.get('interface', 'any')
            filter_expr = network_config.get('filter', '')
            output_name = network_config['output']
            capture_size = network_config.get('capture_size', '100MB')
            
            # Create output directory in logs folder
            output_dir = "logs"
            os.makedirs(output_dir, exist_ok=True)
            
            output_path = os.path.join(output_dir, output_name)
            
            # Build tcpdump command with sudo - run in background
            cmd = [
                'sudo', 'tcpdump',
                '-i', interface,
                '-w', output_path,
                '-s', '0',  # Capture full packet size
                '-U'  # Unbuffered output
            ]
            
            # Use simpler filter or no filter to avoid syntax issues
            if filter_expr:
                # Try to use the full filter expression
                try:
                    # Test if the filter is valid by running tcpdump with -d flag (with sudo)
                    test_cmd = ['sudo', 'tcpdump', '-d', filter_expr]
                    result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=5)
                    
                    if result.returncode == 0:
                        # Filter is valid, use it
                        cmd.append(filter_expr)
                        self.logger.info(f"Using network filter: {filter_expr}")
                    else:
                        # Filter is invalid, try to extract simple parts
                        if 'net' in filter_expr:
                            import re
                            net_matches = re.findall(r'net\s+([^\s/]+)', filter_expr)
                            if net_matches:
                                # Use the first network found
                                simple_filter = f"net {net_matches[0]}"
                                cmd.append(simple_filter)
                                self.logger.info(f"Using simplified network filter: {simple_filter}")
                        elif 'host' in filter_expr:
                            import re
                            host_matches = re.findall(r'host\s+([^\s/]+)', filter_expr)
                            if host_matches:
                                # Use the first host found
                                simple_filter = f"host {host_matches[0]}"
                                cmd.append(simple_filter)
                                self.logger.info(f"Using simplified host filter: {simple_filter}")
                        else:
                            # If no recognizable pattern, don't use filter
                            self.logger.warning(f"Could not parse network filter: {filter_expr}")
                except Exception as e:
                    # If filter parsing fails, don't use any filter
                    self.logger.warning(f"Filter parsing failed: {e}")
                    # Try without filter
                    pass
            else:
                self.logger.info("No network filter specified, capturing all traffic")
            
            # Start tcpdump in background
            try:
                # Kill any existing tcpdump processes
                subprocess.run(['sudo', 'pkill', '-f', 'tcpdump'], 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                # Start tcpdump in background
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                
                # Store process ID for later cleanup
                context.tcpdump_pid = process.pid
                
                # Wait a moment for tcpdump to start
                time.sleep(2)
                
                # Check if process is still running
                if process.poll() is None:  # Process is still running
                    self.logger.info(f"Network capture started (PID: {process.pid}): {output_path}")
                    return output_path
                else:
                    # Check if tcpdump failed to start
                    return_code = process.returncode
                    self.logger.error(f"Network capture failed to start, return code: {return_code}")
                    return None
                    
            except Exception as e:
                self.logger.error(f"Failed to start network capture: {str(e)}")
                return None
            
        except Exception as e:
            self.logger.error(f"Failed to start network capture: {str(e)}")
            return None
    

    
    def collect_all_logs(self, context) -> Dict[str, str]:
        """
        Collect all configured logs and parse them to CSV
        
        Args:
            context: Scenario context
            
        Returns:
            Dict[str, str]: Mapping of log source to parsed CSV file path
        """
        collected_logs = {}
        
        # Collect container and host logs
        log_configs = context.config.get('data_collection', {}).get('logs', [])
        for log_config in log_configs:
            log_file = self.collect_log(log_config, context)
            if log_file:
                # Parse log file to CSV
                csv_file = self.parse_log_to_csv(log_file, log_config, context)
                if csv_file:
                    collected_logs[log_config['source']] = csv_file
                else:
                    collected_logs[log_config['source']] = log_file  # Fallback to raw log
        
        # Special handling for attacker logs - collect all attack_*.log files
        attacker_logs = self.collect_attacker_logs(context)
        if attacker_logs:
            collected_logs['attacker'] = attacker_logs
        
        # Collect network data
        network_configs = context.config.get('data_collection', {}).get('network', [])
        for network_config in network_configs:
            pcap_file = self.capture_network(network_config, context)
            if pcap_file:
                collected_logs['network'] = pcap_file
        
        return collected_logs
    
    def collect_attacker_logs(self, context) -> Optional[str]:
        """
        Collect all attack log files from attacker container
        
        Args:
            context: Scenario context
            
        Returns:
            str: Path to combined attack log file or None if failed
        """
        try:
            # Find attacker container
            attacker_container = None
            for container in context.containers:
                if container.get('name') == 'attacker':
                    attacker_container = container
                    break
            
            if not attacker_container:
                self.logger.warning("Attacker container not found")
                return None
            
            # Get container ID
            container_id = attacker_container.get('id')
            if not container_id:
                self.logger.warning("Attacker container ID not found")
                return None
            
            # List all attack log files in the container
            result = context.docker_client.containers.get(container_id).exec_run(
                'ls -la /logs/attack_*.log 2>/dev/null || echo "No attack logs found"'
            )
            
            if result.exit_code != 0:
                self.logger.warning("Failed to list attack log files")
                return None
            
            log_files = result.output.decode('utf-8').strip().split('\n')
            if not log_files or log_files[0] == "No attack logs found":
                self.logger.warning("No attack log files found")
                return None
            
            # Create output directory
            output_dir = "logs/attacker"
            os.makedirs(output_dir, exist_ok=True)
            
            # Combine all attack logs into one file
            combined_log_path = os.path.join(output_dir, "attack_combined.log")
            
            with open(combined_log_path, 'w') as combined_file:
                for log_file in log_files:
                    if log_file and not log_file.startswith("No attack logs found"):
                        # Extract filename from ls output
                        filename = log_file.split()[-1] if log_file.split() else None
                        if filename and filename.startswith('attack_'):
                            # Copy log file from container
                            try:
                                result = context.docker_client.containers.get(container_id).exec_run(
                                    f'cat {filename}'
                                )
                                if result.exit_code == 0:
                                    combined_file.write(f"=== {filename} ===\n")
                                    combined_file.write(result.output.decode('utf-8'))
                                    combined_file.write("\n\n")
                                    self.logger.info(f"Collected attack log: {filename}")
                            except Exception as e:
                                self.logger.warning(f"Failed to collect {filename}: {str(e)}")
            
            if os.path.getsize(combined_log_path) > 0:
                self.logger.info(f"Combined attack logs: {combined_log_path}")
                return combined_log_path
            else:
                self.logger.warning("No attack log content collected")
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to collect attacker logs: {str(e)}")
            return None
    
    def parse_log_to_csv(self, log_file: str, log_config: Dict, context) -> Optional[str]:
        """
        Parse log file to CSV using appropriate parser
        
        Args:
            log_file: Path to raw log file
            log_config: Log configuration
            context: Scenario context
            
        Returns:
            str: Path to CSV file or None if parsing failed
        """
        try:
            # Get parser type from config
            parser_type = log_config.get('parser', 'application')
            source_name = log_config.get('source', 'unknown')
            
            # Create CSV output path in output directory instead of logs
            csv_filename = log_config.get('output', f"{source_name}.csv")
            csv_dir = "output"
            os.makedirs(csv_dir, exist_ok=True)
            csv_file = os.path.join(csv_dir, csv_filename)
            
            # Import and use appropriate parser from flattened structure
            if parser_type == 'nginx_parser':
                from parsers.nginx_parser import NginxParser
                parser = NginxParser(source_name)
            elif parser_type == 'user_parser':
                from parsers.user_parser import UserParser
                parser = UserParser(source_name)
            elif parser_type == 'attack_parser':
                from parsers.attack_parser import AttackParser
                parser = AttackParser(source_name)
            elif parser_type == 'pcap_parser':
                from parsers.pcap_parser import PcapParser
                parser = PcapParser(source_name)
            else:
                # Default to user parser
                from parsers.user_parser import UserParser
                parser = UserParser(source_name)
            
            # Parse the log file
            parsed_count = parser.parse_file(log_file, csv_file)
            
            if parsed_count > 0:
                self.logger.info(f"Parsed {parsed_count} lines from {log_file} to {csv_file}")
                return csv_file
            else:
                self.logger.warning(f"No lines parsed from {log_file}")
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to parse log file {log_file}: {str(e)}")
            return None
    
    def wait_for_log_file(self, log_path: str, timeout: int = 60) -> bool:
        """
        Wait for log file to be created and have content
        
        Args:
            log_path: Path to log file
            timeout: Timeout in seconds
            
        Returns:
            bool: True if log file is ready
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if os.path.exists(log_path):
                # Check if file has content
                try:
                    with open(log_path, 'r') as f:
                        content = f.read().strip()
                        if content:
                            return True
                except Exception:
                    pass
            
            time.sleep(1)
        
        return False
    
    def get_log_stats(self, log_path: str) -> Dict:
        """
        Get statistics about a log file
        
        Args:
            log_path: Path to log file
            
        Returns:
            Dict: Log file statistics
        """
        try:
            if not os.path.exists(log_path):
                return {'error': 'File not found'}
            
            stat = os.stat(log_path)
            
            # Count lines
            line_count = 0
            try:
                with open(log_path, 'r') as f:
                    line_count = sum(1 for _ in f)
            except Exception:
                pass
            
            return {
                'size_bytes': stat.st_size,
                'line_count': line_count,
                'modified_time': stat.st_mtime,
                'created_time': stat.st_ctime
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def cleanup_logs(self, context):
        """Cleanup temporary log files"""
        try:
            # Stop network capture
            self.stop_network_capture(context)
            
            # Remove temporary files
            temp_dir = "/tmp"
            for file in os.listdir(temp_dir):
                if file.startswith("cyberrange_"):
                    temp_file = os.path.join(temp_dir, file)
                    try:
                        os.remove(temp_file)
                    except Exception:
                        pass
            
            self.logger.info("Log cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup logs: {str(e)}")


def main():
    """Test the LogCollector"""
    collector = LogCollector()
    
    # Test log stats
    test_log = "scenario.log"
    if os.path.exists(test_log):
        stats = collector.get_log_stats(test_log)
        print(f"Log stats for {test_log}:")
        for key, value in stats.items():
            print(f"  {key}: {value}")


if __name__ == "__main__":
    main() 