#!/usr/bin/env python3
"""
Container Manager for CyberRange
Manages Docker containers and networks using Docker Python SDK
"""

import docker
import logging
import time
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class ContainerInfo:
    """Container information"""
    id: str
    name: str
    status: str
    ip_address: str
    ports: Dict
    networks: List[str]


class ContainerManager:
    def __init__(self):
        """Initialize ContainerManager with Docker client"""
        try:
            self.client = docker.from_env()
            self.logger = logging.getLogger(__name__)
            self.project_root = self._get_project_root()
            self.logger.info("Docker client initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize Docker client: {str(e)}")
            raise
    
    def create_network(self, network_config: Dict) -> bool:
        """
        Create Docker network
        
        Args:
            network_config: Network configuration dictionary
            
        Returns:
            bool: True if network created successfully
        """
        try:
            network_name = network_config['name']
            driver = network_config.get('driver', 'bridge')
            subnet = network_config.get('subnet')
            gateway = network_config.get('gateway')
            
            # Check if network already exists
            try:
                existing_network = self.client.networks.get(network_name)
                self.logger.info(f"Network {network_name} already exists")
                return True
            except docker.errors.NotFound:
                pass
            
            # Create network
            ipam_config = None
            if subnet:
                ipam_config = docker.types.IPAMConfig(
                    driver='default',
                    pool_configs=[
                        docker.types.IPAMPool(
                            subnet=subnet,
                            gateway=gateway
                        )
                    ]
                )
            
            network = self.client.networks.create(
                name=network_name,
                driver=driver,
                ipam=ipam_config
            )
            
            self.logger.info(f"Created network: {network_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create network {network_config.get('name', 'Unknown')}: {str(e)}")
            return False
    
    def start_container(self, node_config: Dict) -> Optional[ContainerInfo]:
        """
        Start a Docker container
        
        Args:
            node_config: Node configuration dictionary
            
        Returns:
            ContainerInfo: Container information or None if failed
        """
        try:
            container_name = node_config['name']
            image = node_config['image']
            
            # Create necessary directories for volumes
            if not self._create_volume_directories(node_config):
                self.logger.error(f"Failed to create volume directories for {container_name}")
                return None
            
            # Check if container already exists and remove it
            try:
                existing_container = self.client.containers.get(container_name)
                self.logger.info(f"Removing existing container: {container_name}")
                existing_container.remove(force=True)
            except docker.errors.NotFound:
                pass
            
            # Prepare container configuration
            container_config = self._prepare_container_config(node_config)
            
            # Create and start container
            # Remove additional_networks from config as it's not a valid parameter
            additional_networks = container_config.pop('additional_networks', [])
            
            self.logger.info(f"Starting container with config: {container_config}")
            self.logger.info(f"Container name: {container_name}, Image: {image}")
            container = self.client.containers.run(
                image=image,
                name=container_name,
                detach=True,
                **container_config
            )
            
            self.logger.info(f"Started container: {container_name} ({container.id})")
            
            # Wait for container to be ready
            if not self.wait_for_container_ready(container.id):
                self.logger.error(f"Container {container_name} failed to start properly")
                return None
            
            # Connect to additional networks if specified
            for network_name in additional_networks:
                try:
                    network = self.client.networks.get(network_name)
                    
                    # Check if there are aliases for this network
                    aliases = None
                    if 'network_aliases' in node_config and network_name in node_config['network_aliases']:
                        aliases = node_config['network_aliases'][network_name]
                    
                    if aliases:
                        network.connect(container.id, aliases=aliases)
                        self.logger.info(f"Connected {container_name} to network: {network_name} with aliases: {aliases}")
                    else:
                        network.connect(container.id)
                        self.logger.info(f"Connected {container_name} to network: {network_name}")
                except Exception as e:
                    self.logger.warning(f"Failed to connect {container_name} to network {network_name}: {e}")
            
            # Set network aliases for primary network if specified
            if 'network_aliases' in node_config and container_config['network'] in node_config['network_aliases']:
                try:
                    primary_network = self.client.networks.get(container_config['network'])
                    aliases = node_config['network_aliases'][container_config['network']]
                    # Disconnect and reconnect with aliases
                    primary_network.disconnect(container.id, force=True)
                    primary_network.connect(container.id, aliases=aliases)
                    self.logger.info(f"Set aliases {aliases} for {container_name} on primary network {container_config['network']}")
                except Exception as e:
                    self.logger.warning(f"Failed to set network aliases for {container_name}: {e}")
            
            # Get container information
            container_info = self._get_container_info(container)
            return container_info
            
        except Exception as e:
            self.logger.error(f"Failed to start container {node_config.get('name', 'Unknown')}: {str(e)}")
            return None
    
    def _prepare_container_config(self, node_config: Dict) -> Dict:
        """Prepare container configuration from node config"""
        config = {}
        
        # Port mappings
        if 'ports' in node_config:
            config['ports'] = {}
            self.logger.info(f"Processing ports: {node_config['ports']}")
            for port_mapping in node_config['ports']:
                try:
                    if isinstance(port_mapping, str):
                        # Format: "host_port:container_port"
                        host_port, container_port = port_mapping.split(':')
                        config['ports'][container_port] = int(host_port)
                        self.logger.info(f"Added port mapping: {container_port} -> {host_port}")
                    else:
                        # Format: [host_port, container_port]
                        config['ports'][str(port_mapping[1])] = port_mapping[0]
                        self.logger.info(f"Added port mapping: {port_mapping[1]} -> {port_mapping[0]}")
                except Exception as e:
                    self.logger.warning(f"Invalid port mapping format: {port_mapping}, error: {e}")
                    continue
        
        # Network configuration - support multiple networks
        if 'networks' in node_config:
            if len(node_config['networks']) == 1:
                config['network'] = node_config['networks'][0]
            else:
                # For multiple networks, we'll connect after creation
                config['network'] = node_config['networks'][0]  # Primary network
                config['additional_networks'] = node_config['networks'][1:]
        
        # Volume mappings
        if 'volumes' in node_config:
            config['volumes'] = {}
            for volume_mapping in node_config['volumes']:
                if isinstance(volume_mapping, str):
                    # Format: "host_path:container_path" or "host_path:container_path:ro"
                    parts = volume_mapping.split(':')
                    if len(parts) < 2 or len(parts) > 3:
                        self.logger.warning(f"Invalid volume mapping format: {volume_mapping}")
                        continue
                    host_path = self._resolve_host_path(parts[0])
                    container_path = parts[1]
                    mode = 'ro' if len(parts) == 3 and parts[2] == 'ro' else 'rw'
                    config['volumes'][host_path] = {'bind': container_path, 'mode': mode}
        
        # Environment variables
        if 'environment' in node_config:
            config['environment'] = node_config['environment']
        
        # Extra hosts for domain name resolution
        if 'extra_hosts' in node_config:
            config['extra_hosts'] = {}
            for host_mapping in node_config['extra_hosts']:
                if ':' in host_mapping:
                    host, ip = host_mapping.split(':', 1)
                    config['extra_hosts'][host] = ip
        
        # Command
        if 'command' in node_config:
            config['command'] = node_config['command']
        
        # Health check
        if 'health_check' in node_config:
            health_config = node_config['health_check']
            
            # Handle different health check types
            if 'url' in health_config:
                # HTTP health check
                test_cmd = ['CMD-SHELL', f'curl -f {health_config["url"]} || exit 1']
            elif 'command' in health_config:
                # Custom command health check
                test_cmd = health_config['command']
            else:
                # Default health check
                test_cmd = ['CMD-SHELL', 'true']
            
            config['healthcheck'] = docker.types.Healthcheck(
                test=test_cmd,
                interval=health_config.get('interval', 30),
                timeout=health_config.get('timeout', 10),
                retries=health_config.get('retries', 3)
            )
        
        return config
    
    def _create_volume_directories(self, node_config: Dict) -> bool:
        """
        Create necessary directories for volume mounts
        
        Returns:
            bool: True if all directories created successfully, False otherwise
        """
        import os
        
        if 'volumes' not in node_config:
            self.logger.debug("No volumes configured for this node")
            return True
            
        success = True
        self.logger.info(f"Processing volumes: {node_config['volumes']}")
        
        for volume_mapping in node_config['volumes']:
            try:
                if isinstance(volume_mapping, str):
                    # Format: "host_path:container_path" or "host_path:container_path:ro"
                    parts = volume_mapping.split(':')
                    if len(parts) < 2 or len(parts) > 3:
                        self.logger.warning(f"Invalid volume mapping format: {volume_mapping}")
                        continue
                    host_path = self._resolve_host_path(parts[0])
                    
                    # Create directory if it doesn't exist
                    if not os.path.exists(host_path):
                        os.makedirs(host_path, exist_ok=True)
                        self.logger.info(f"Created directory: {host_path}")
                    else:
                        self.logger.debug(f"Directory already exists: {host_path}")
                        
                else:
                    # Format: [host_path, container_path]
                    if len(volume_mapping) < 1:
                        self.logger.warning(f"Invalid volume mapping format: {volume_mapping}")
                        continue
                    host_path = self._resolve_host_path(volume_mapping[0])
                    
                    if not os.path.exists(host_path):
                        os.makedirs(host_path, exist_ok=True)
                        self.logger.info(f"Created directory: {host_path}")
                    else:
                        self.logger.debug(f"Directory already exists: {host_path}")
                        
            except Exception as e:
                self.logger.error(f"Failed to create volume directory for {volume_mapping}: {str(e)}")
                success = False
                
        return success
    
    def _get_container_info(self, container) -> ContainerInfo:
        """Extract container information from Docker container object"""
        container.reload()
        
        # Get IP address
        ip_address = ""
        if container.attrs['NetworkSettings']['Networks']:
            network_name = list(container.attrs['NetworkSettings']['Networks'].keys())[0]
            ip_address = container.attrs['NetworkSettings']['Networks'][network_name]['IPAddress']
        
        # Get port mappings
        ports = {}
        if container.attrs['NetworkSettings']['Ports']:
            for container_port, host_bindings in container.attrs['NetworkSettings']['Ports'].items():
                if host_bindings:
                    ports[container_port] = host_bindings[0]['HostPort']
        
        # Get networks
        networks = list(container.attrs['NetworkSettings']['Networks'].keys())
        
        return ContainerInfo(
            id=container.id,
            name=container.name,
            status=container.status,
            ip_address=ip_address,
            ports=ports,
            networks=networks
        )
    
    def stop_container(self, container_id: str) -> bool:
        """
        Stop a Docker container
        
        Args:
            container_id: Container ID or name
            
        Returns:
            bool: True if container stopped successfully
        """
        try:
            container = self.client.containers.get(container_id)
            container.stop(timeout=30)
            self.logger.info(f"Stopped container: {container_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to stop container {container_id}: {str(e)}")
            return False
    
    def remove_container(self, container_id: str) -> bool:
        """
        Remove a Docker container
        
        Args:
            container_id: Container ID or name
            
        Returns:
            bool: True if container removed successfully
        """
        try:
            container = self.client.containers.get(container_id)
            container.remove(force=True)
            self.logger.info(f"Removed container: {container_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to remove container {container_id}: {str(e)}")
            return False
    
    def remove_network(self, network_name: str) -> bool:
        """
        Remove a Docker network
        
        Args:
            network_name: Network name
            
        Returns:
            bool: True if network removed successfully
        """
        try:
            network = self.client.networks.get(network_name)
            network.remove()
            self.logger.info(f"Removed network: {network_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to remove network {network_name}: {str(e)}")
            return False
    
    def get_container_status(self, container_id: str) -> Optional[str]:
        """
        Get container status
        
        Args:
            container_id: Container ID or name
            
        Returns:
            str: Container status or None if not found
        """
        try:
            container = self.client.containers.get(container_id)
            container.reload()
            return container.status
            
        except Exception as e:
            self.logger.error(f"Failed to get container status {container_id}: {str(e)}")
            return None
    
    def wait_for_container_ready(self, container_id: str, timeout: int = 300) -> bool:
        """
        Wait for container to be ready
        
        Args:
            container_id: Container ID or name
            timeout: Timeout in seconds
            
        Returns:
            bool: True if container is ready within timeout
        """
        try:
            container = self.client.containers.get(container_id)
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                container.reload()
                
                if container.status == 'running':
                    # Check health status if health check is configured
                    if container.attrs['State'].get('Health'):
                        health_status = container.attrs['State']['Health']['Status']
                        if health_status == 'healthy':
                            self.logger.info(f"Container {container_id} is healthy")
                            return True
                    else:
                        # No health check, consider running as ready
                        self.logger.info(f"Container {container_id} is running")
                        return True
                
                time.sleep(5)
            
            self.logger.warning(f"Container {container_id} not ready within {timeout} seconds")
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to wait for container {container_id}: {str(e)}")
            return False
    
    def list_containers(self) -> List[ContainerInfo]:
        """
        List all containers
        
        Returns:
            List[ContainerInfo]: List of container information
        """
        containers = []
        try:
            for container in self.client.containers.list(all=True):
                container_info = self._get_container_info(container)
                containers.append(container_info)
        except Exception as e:
            self.logger.error(f"Failed to list containers: {str(e)}")
        
        return containers
    
    def list_networks(self) -> List[Dict]:
        """
        List all networks
        
        Returns:
            List[Dict]: List of network information
        """
        networks = []
        try:
            for network in self.client.networks.list():
                networks.append({
                    'id': network.id,
                    'name': network.name,
                    'driver': network.attrs['Driver'],
                    'scope': network.attrs['Scope']
                })
        except Exception as e:
            self.logger.error(f"Failed to list networks: {str(e)}")
        
        return networks
    
    def _get_project_root(self) -> str:
        """Get the project root directory"""
        # Go up from orchestrator to project root
        from pathlib import Path
        return str(Path(__file__).parent.parent.absolute())
    
    def _resolve_host_path(self, path: str) -> str:
        """
        Resolve host path to absolute path
        
        Args:
            path: Input path (can be relative or absolute)
            
        Returns:
            str: Resolved absolute path
        """
        import os
        
        # If already absolute, return as is
        if os.path.isabs(path):
            return path
        
        # If relative, make it relative to project root
        resolved_path = os.path.join(self.project_root, path)
        return os.path.abspath(resolved_path)


def main():
    """Test the ContainerManager"""
    manager = ContainerManager()
    
    # List existing containers and networks
    print("Existing containers:")
    for container in manager.list_containers():
        print(f"  {container.name}: {container.status}")
    
    print("\nExisting networks:")
    for network in manager.list_networks():
        print(f"  {network['name']}: {network['driver']}")


if __name__ == "__main__":
    main() 