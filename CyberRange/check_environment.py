#!/usr/bin/env python3
"""
Environment Check Script for CyberRange
Verifies that all dependencies and requirements are met before running scenarios
"""

import os
import sys
import subprocess
import logging
import importlib
from pathlib import Path
from typing import List, Tuple, Dict


class EnvironmentChecker:
    """Check environment requirements for CyberRange"""
    
    def __init__(self):
        self.setup_logging()
        self.logger = logging.getLogger(__name__)
        self.project_root = Path(__file__).parent.absolute()
        self.errors = []
        self.warnings = []
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def check_all(self, auto_pull_images: bool = True) -> bool:
        """
        Run all environment checks
        
        Args:
            auto_pull_images: Whether to auto-pull missing Docker images
        
        Returns:
            bool: True if environment is ready, False otherwise
        """
        self.logger.info("Starting environment check for CyberRange...")
        
        checks = [
            ("Python Version", self.check_python_version),
            ("Python Packages", self.check_python_packages),
            ("Docker", self.check_docker),
            ("Docker Images", lambda: self.check_docker_images(auto_pull_images)),
            ("Project Structure", self.check_project_structure),
            ("Directory Permissions", self.check_directory_permissions),
            ("Configuration Files", self.check_configuration_files),
            ("System Tools", self.check_system_tools)
        ]
        
        results = {}
        for check_name, check_func in checks:
            self.logger.info(f"Checking {check_name}...")
            try:
                results[check_name] = check_func()
                if results[check_name]:
                    self.logger.info(f"✅ {check_name}: PASS")
                else:
                    self.logger.error(f"❌ {check_name}: FAIL")
            except Exception as e:
                self.logger.error(f"❌ {check_name}: ERROR - {str(e)}")
                results[check_name] = False
        
        # Print summary
        self.print_summary(results)
        
        # Return True if all checks passed
        return all(results.values()) and len(self.errors) == 0
    
    def check_python_version(self) -> bool:
        """Check Python version (3.8+)"""
        version = sys.version_info
        if version.major == 3 and version.minor >= 8:
            self.logger.debug(f"Python version: {version.major}.{version.minor}.{version.micro}")
            return True
        else:
            self.errors.append(f"Python 3.8+ required, found {version.major}.{version.minor}.{version.micro}")
            return False
    
    def check_python_packages(self) -> bool:
        """Check required Python packages"""
        required_packages = [
            'docker',
            'yaml',
            'pathlib',
            'argparse'
        ]
        
        missing_packages = []
        for package in required_packages:
            try:
                if package == 'yaml':
                    importlib.import_module('yaml')
                else:
                    importlib.import_module(package)
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            self.errors.append(f"Missing Python packages: {', '.join(missing_packages)}")
            self.logger.error("Install missing packages with: pip install " + " ".join(missing_packages))
            return False
        
        return True
    
    def check_docker(self) -> bool:
        """Check Docker installation and daemon"""
        try:
            # Check if docker command exists
            result = subprocess.run(['docker', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                self.errors.append("Docker command not found")
                return False
            
            # Check if Docker daemon is running
            result = subprocess.run(['docker', 'info'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                self.errors.append("Docker daemon is not running")
                self.logger.error("Start Docker daemon with: sudo systemctl start docker")
                return False
            
            # Check Docker permissions
            result = subprocess.run(['docker', 'ps'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                if "permission denied" in result.stderr.lower():
                    self.warnings.append("Docker requires sudo permissions")
                    self.logger.warning("Add user to docker group: sudo usermod -aG docker $USER")
                    # This is a warning, not an error
                else:
                    self.errors.append("Cannot list Docker containers")
                    return False
            
            return True
            
        except FileNotFoundError:
            self.errors.append("Docker is not installed")
            self.logger.error("Install Docker: https://docs.docker.com/engine/install/")
            return False
        except subprocess.TimeoutExpired:
            self.errors.append("Docker command timed out")
            return False
    
    def check_docker_images(self, auto_pull: bool = True) -> bool:
        """Check if required Docker images exist and auto-pull/build if needed"""
        # These images can be pulled from Docker Hub
        pullable_images = [
            'nginx:alpine',           # Reverse proxy for juice-shop
            'python:3.9-slim',       # For benign user simulation
            'bkimminich/juice-shop'   # Target application
        ]
        
        # These images need to be built locally (all are required)
        buildable_images = [
            'ras-attacker:latest'     # Attack simulation container
        ]
        
        try:
            missing_pullable = []
            missing_buildable = []
            
            # Check pullable images
            for image in pullable_images:
                result = subprocess.run(['docker', 'image', 'inspect', image], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    missing_pullable.append(image)
                    self.logger.info(f"Pullable image {image} not found locally")
            
            # Check buildable images
            for image in buildable_images:
                result = subprocess.run(['docker', 'image', 'inspect', image], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    missing_buildable.append(image)
                    self.logger.info(f"Buildable image {image} not found locally")
            
            # Auto-pull missing pullable images
            if missing_pullable and auto_pull:
                self.logger.info("Auto-pulling missing Docker images...")
                for image in missing_pullable:
                    success = self._pull_docker_image(image)
                    if not success:
                        self.errors.append(f"Failed to pull required image: {image}")
                        return False
            elif missing_pullable and not auto_pull:
                self.errors.append(f"Missing pullable images: {', '.join(missing_pullable)}")
                return False
            
            # Handle buildable images
            if missing_buildable:
                if auto_pull:  # When auto_pull is True, try to build missing images
                    self.logger.info("Auto-building missing Docker images...")
                    for image in missing_buildable:
                        if image == 'ras-attacker:latest':
                            success = self._build_attacker_image()
                            if not success:
                                self.errors.append(f"Failed to build required image: {image}")
                                return False
                else:
                    self.errors.append(f"Missing buildable images: {', '.join(missing_buildable)}")
                    self.logger.error("Build missing images with: python check_environment.py --fix")
                    return False
            
            return True
            
        except subprocess.TimeoutExpired:
            self.warnings.append("Docker image check timed out")
            return True  # Not critical
    
    def check_project_structure(self) -> bool:
        """Check project directory structure"""
        required_dirs = [
            'orchestrator',
            'parsers',
            'scenarios',
            'hooks',
            'scenario-securitylogs'
        ]
        
        required_files = [
            'run_scenario.py',
            'orchestrator/__init__.py',
            'parsers/__init__.py',
            'parsers/parse_logs.py'
        ]
        
        missing_dirs = []
        for dir_name in required_dirs:
            dir_path = self.project_root / dir_name
            if not dir_path.exists():
                missing_dirs.append(str(dir_path))
        
        missing_files = []
        for file_name in required_files:
            file_path = self.project_root / file_name
            if not file_path.exists():
                missing_files.append(str(file_path))
        
        if missing_dirs or missing_files:
            if missing_dirs:
                self.errors.append(f"Missing directories: {', '.join(missing_dirs)}")
            if missing_files:
                self.errors.append(f"Missing files: {', '.join(missing_files)}")
            return False
        
        return True
    
    def check_directory_permissions(self) -> bool:
        """Check directory permissions for log and output directories"""
        dirs_to_check = [
            self.project_root,
            self.project_root / 'logs',
            self.project_root / 'output'
        ]
        
        permission_errors = []
        for dir_path in dirs_to_check:
            # Create directory if it doesn't exist
            if not dir_path.exists():
                try:
                    dir_path.mkdir(parents=True, exist_ok=True)
                    self.logger.info(f"Created directory: {dir_path}")
                except PermissionError:
                    permission_errors.append(f"Cannot create directory: {dir_path}")
                    continue
            
            # Check if we can write to the directory
            test_file = dir_path / '.test_write'
            try:
                test_file.touch()
                test_file.unlink()
            except PermissionError:
                permission_errors.append(f"Cannot write to directory: {dir_path}")
        
        if permission_errors:
            self.errors.extend(permission_errors)
            return False
        
        return True
    
    def check_configuration_files(self) -> bool:
        """Check if configuration files exist and are valid"""
        config_dir = self.project_root / 'scenarios'
        
        if not config_dir.exists():
            self.errors.append(f"Configuration directory not found: {config_dir}")
            return False
        
        # Look for YAML files
        yaml_files = list(config_dir.glob('*.yaml')) + list(config_dir.glob('*.yml'))
        
        if not yaml_files:
            self.warnings.append("No YAML configuration files found in scenarios/")
            self.logger.info("You can create a simple config with: python -c \"from orchestrator.modular_adapter import create_simple_config_template; create_simple_config_template('scenarios/my-scenario.yaml')\"")
        else:
            self.logger.info(f"Found {len(yaml_files)} configuration files")
            
            # Try to parse one config file as a test
            import yaml
            test_file = yaml_files[0]
            try:
                with open(test_file, 'r') as f:
                    yaml.safe_load(f)
                self.logger.debug(f"Successfully parsed test config: {test_file.name}")
            except Exception as e:
                self.warnings.append(f"Config file {test_file.name} may have syntax errors: {e}")
        
        return True
    
    def check_system_tools(self) -> bool:
        """Check for required system tools"""
        required_tools = ['tcpdump']
        optional_tools = ['tshark', 'wireshark']
        
        missing_required = []
        missing_optional = []
        
        for tool in required_tools:
            if not self.check_command_exists(tool):
                missing_required.append(tool)
        
        for tool in optional_tools:
            if not self.check_command_exists(tool):
                missing_optional.append(tool)
        
        if missing_required:
            self.errors.append(f"Missing required tools: {', '.join(missing_required)}")
            self.logger.error("Install tcpdump: sudo apt-get install tcpdump")
            return False
        
        if missing_optional:
            self.warnings.append(f"Missing optional tools: {', '.join(missing_optional)}")
        
        return True
    
    def check_command_exists(self, command: str) -> bool:
        """Check if a command exists in PATH"""
        try:
            subprocess.run(['which', command], 
                         capture_output=True, text=True, timeout=5)
            return True
        except:
            return False
    
    def _pull_docker_image(self, image: str) -> bool:
        """
        Pull a Docker image
        
        Args:
            image: Docker image name to pull
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.logger.info(f"Pulling Docker image: {image}")
            result = subprocess.run(
                ['docker', 'pull', image], 
                capture_output=True, 
                text=True, 
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode == 0:
                self.logger.info(f"✅ Successfully pulled image: {image}")
                return True
            else:
                self.logger.error(f"Failed to pull image {image}: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout pulling image: {image}")
            return False
        except Exception as e:
            self.logger.error(f"Error pulling image {image}: {e}")
            return False
    
    def _build_docker_image(self, image_name: str, dockerfile_path: str = None) -> bool:
        """
        Build a Docker image if Dockerfile exists
        
        Args:
            image_name: Name for the built image
            dockerfile_path: Path to Dockerfile directory
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not dockerfile_path:
                # Try to find Dockerfile in common locations
                possible_paths = [
                    self.project_root / 'scenario-securitylogs' / 'confs' / 'attacker',
                    self.project_root / 'docker' / 'attacker',
                    self.project_root / 'dockerfiles' / 'attacker'
                ]
                
                dockerfile_path = None
                for path in possible_paths:
                    if (path / 'Dockerfile').exists():
                        dockerfile_path = str(path)
                        break
                
                if not dockerfile_path:
                    self.logger.warning(f"No Dockerfile found for {image_name}")
                    return False
            
            self.logger.info(f"Building Docker image: {image_name}")
            result = subprocess.run(
                ['docker', 'build', '-t', image_name, dockerfile_path],
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes timeout
            )
            
            if result.returncode == 0:
                self.logger.info(f"✅ Successfully built image: {image_name}")
                return True
            else:
                self.logger.error(f"Failed to build image {image_name}: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout building image: {image_name}")
            return False
        except Exception as e:
            self.logger.error(f"Error building image {image_name}: {e}")
            return False
    
    def _build_attacker_image(self) -> bool:
        """
        Build the ras-attacker Docker image
        
        Returns:
            bool: True if successful, False otherwise
        """
        attacker_dockerfile_dir = self.project_root / 'scenario-securitylogs' / 'confs' / 'attacker'
        
        if not (attacker_dockerfile_dir / 'Dockerfile').exists():
            self.logger.error(f"Dockerfile not found in {attacker_dockerfile_dir}")
            self.logger.error("Make sure scenario-securitylogs/confs/attacker/Dockerfile exists")
            return False
        
        return self._build_docker_image('ras-attacker:latest', str(attacker_dockerfile_dir))
    
    def print_summary(self, results: Dict[str, bool]):
        """Print summary of all checks"""
        print("\n" + "="*60)
        print("ENVIRONMENT CHECK SUMMARY")
        print("="*60)
        
        passed = sum(1 for result in results.values() if result)
        total = len(results)
        
        print(f"Checks passed: {passed}/{total}")
        
        if self.errors:
            print(f"\n❌ ERRORS ({len(self.errors)}):")
            for i, error in enumerate(self.errors, 1):
                print(f"  {i}. {error}")
        
        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for i, warning in enumerate(self.warnings, 1):
                print(f"  {i}. {warning}")
        
        if passed == total and not self.errors:
            print(f"\n✅ Environment is ready for CyberRange!")
            print("You can now run scenarios with: python run_scenario.py --config <config_file>")
        else:
            print(f"\n❌ Environment needs attention before running CyberRange")
            print("Please fix the errors above and run this check again")
        
        print("="*60)
    
    def fix_common_issues(self):
        """Attempt to fix common issues automatically"""
        self.logger.info("Attempting to fix common issues...")
        
        # Create missing directories
        dirs_to_create = ['logs', 'output', 'logs/nginx', 'logs/attacker', 'logs/benign_user']
        for dir_name in dirs_to_create:
            dir_path = self.project_root / dir_name
            if not dir_path.exists():
                try:
                    dir_path.mkdir(parents=True, exist_ok=True)
                    self.logger.info(f"Created directory: {dir_path}")
                except Exception as e:
                    self.logger.error(f"Failed to create directory {dir_path}: {e}")
        
        # Pull missing Docker images
        self.logger.info("Checking and pulling missing Docker images...")
        pullable_images = ['nginx:alpine', 'python:3.9-slim', 'bkimminich/juice-shop']
        
        for image in pullable_images:
            try:
                result = subprocess.run(['docker', 'image', 'inspect', image], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    self._pull_docker_image(image)
            except Exception as e:
                self.logger.warning(f"Failed to check/pull image {image}: {e}")
        
        # Build required attacker image if missing
        try:
            result = subprocess.run(['docker', 'image', 'inspect', 'ras-attacker:latest'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                self.logger.info("Building required ras-attacker image...")
                self._build_attacker_image()
        except Exception as e:
            self.logger.warning(f"Failed to build ras-attacker image: {e}")
        
        # Create a sample configuration if none exists
        config_dir = self.project_root / 'scenarios'
        yaml_files = list(config_dir.glob('*.yaml')) + list(config_dir.glob('*.yml'))
        if not yaml_files:
            try:
                from orchestrator.modular_adapter import create_simple_config_template
                sample_config = config_dir / 'sample-scenario.yaml'
                create_simple_config_template(str(sample_config), 'sample-scenario')
                self.logger.info(f"Created sample configuration: {sample_config}")
            except Exception as e:
                self.logger.error(f"Failed to create sample configuration: {e}")


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Check CyberRange environment requirements",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--fix',
        action='store_true',
        help='Attempt to fix common issues automatically'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--no-pull',
        action='store_true',
        help='Do not auto-pull missing Docker images'
    )
    
    parser.add_argument(
        '--build-images',
        action='store_true',
        help='Attempt to build missing optional Docker images'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    checker = EnvironmentChecker()
    
    if args.fix:
        checker.fix_common_issues()
    
    # Determine auto-pull setting
    auto_pull = not args.no_pull
    
    success = checker.check_all(auto_pull_images=auto_pull)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
