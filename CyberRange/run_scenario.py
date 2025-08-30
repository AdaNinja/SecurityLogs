#!/usr/bin/env python3
"""
CyberRange Scenario Runner
Main entry point for running attack simulation scenarios
"""

import os
import sys
import argparse
import logging
import yaml
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from orchestrator import ScenarioManager, ErrorHandler


def resolve_config_path(config_path: str) -> Optional[str]:
    """
    Resolve configuration file path by trying multiple locations
    
    Args:
        config_path: Input configuration path (can be relative, absolute, or just filename)
        
    Returns:
        str: Resolved absolute path or None if not found
    """
    # Get the project root directory (where this script is located)
    project_root = os.path.dirname(os.path.abspath(__file__))
    
    # List of paths to try, in order of preference
    paths_to_try = []
    
    # If it's already an absolute path, try it first
    if os.path.isabs(config_path):
        paths_to_try.append(config_path)
    else:
        # Try relative to current directory
        paths_to_try.append(os.path.abspath(config_path))
        
        # Try relative to project root
        paths_to_try.append(os.path.join(project_root, config_path))
        
        # If it's just a filename, try in scenarios directory
        if not os.path.dirname(config_path):
            paths_to_try.append(os.path.join(project_root, 'scenarios', config_path))
        
        # Also try adding .yaml extension if not present
        if not config_path.endswith('.yaml') and not config_path.endswith('.yml'):
            paths_to_try.append(os.path.join(project_root, 'scenarios', config_path + '.yaml'))
    
    # Try each path and return the first one that exists
    for path in paths_to_try:
        if os.path.exists(path):
            return os.path.abspath(path)
    
    return None


def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """Setup logging configuration"""
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('cyberrange.log'),
            logging.StreamHandler()
        ]
    )
    
    return logging.getLogger(__name__)


def validate_config(config: Dict) -> bool:
    """Validate scenario configuration"""
    logger = logging.getLogger(__name__)
    
    required_sections = ['scenario', 'infrastructure', 'behaviors', 'data_collection']
    
    for section in required_sections:
        if section not in config:
            logger.error(f"Missing required section: {section}")
            return False
    
    # Validate scenario section
    scenario = config['scenario']
    if 'name' not in scenario:
        logger.error("Missing scenario name")
        return False
    
    # Validate infrastructure section
    infra = config['infrastructure']
    if 'nodes' not in infra:
        logger.error("Missing nodes in infrastructure")
        return False
    
    # Validate behaviors section
    behaviors = config['behaviors']
    if 'attacks' not in behaviors and 'benign_traffic' not in behaviors:
        logger.error("At least one of 'attacks' or 'benign_traffic' must be defined")
        return False
    
    # Validate data_collection section
    data_collection = config['data_collection']
    if 'logs' not in data_collection:
        logger.error("Missing logs in data_collection")
        return False
    
    logger.info("Configuration validation passed")
    return True


def load_config(config_path: str) -> Optional[Dict]:
    """Load and validate configuration file with modular adapter support"""
    logger = logging.getLogger(__name__)
    
    # Try to find the configuration file in multiple locations
    resolved_path = resolve_config_path(config_path)
    if not resolved_path:
        logger.error(f"Configuration file not found in any of the expected locations")
        logger.error(f"Searched for: {config_path}")
        logger.error(f"Try using one of these formats:")
        logger.error(f"  - Absolute path: /full/path/to/config.yaml")
        logger.error(f"  - Relative to project: scenarios/config.yaml")
        logger.error(f"  - Just filename: config.yaml (will search in scenarios/)")
        return None
    
    config_path = resolved_path
    
    try:
        # Try to use modular adapter first
        try:
            from orchestrator.modular_adapter import load_config_with_adapter
            config = load_config_with_adapter(config_path)
            if config:
                logger.info(f"Loaded configuration from: {config_path} (modular format)")
            else:
                # Fallback to direct loading
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                logger.info(f"Loaded configuration from: {config_path} (detailed format)")
        except ImportError:
            # Fallback to direct loading if modular adapter not available
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            logger.info(f"Loaded configuration from: {config_path} (direct loading)")
        
        if not validate_config(config):
            return None
        
        return config
        
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML file: {e}")
        return None
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return None


def dry_run(config: Dict) -> bool:
    """Perform dry run to validate configuration without execution"""
    logger = logging.getLogger(__name__)
    
    logger.info("=== DRY RUN MODE ===")
    
    # Display scenario information
    scenario = config['scenario']
    logger.info(f"Scenario: {scenario['name']}")
    logger.info(f"Description: {scenario.get('description', 'N/A')}")
    logger.info(f"Duration: {scenario.get('duration', 'N/A')} seconds")
    logger.info(f"Random Seed: {scenario.get('random_seed', 'N/A')}")
    
    # Display infrastructure
    infra = config['infrastructure']
    logger.info(f"\nInfrastructure:")
    logger.info(f"  Networks: {len(infra.get('networks', []))}")
    logger.info(f"  Nodes: {len(infra.get('nodes', []))}")
    
    for node in infra.get('nodes', []):
        logger.info(f"    - {node['name']} ({node['role']}) - {node['image']}")
    
    # Display behaviors
    behaviors = config['behaviors']
    logger.info(f"\nBehaviors:")
    
    if 'attacks' in behaviors:
        logger.info(f"  Attacks: {len(behaviors['attacks'])}")
        for attack in behaviors['attacks']:
            logger.info(f"    - {attack['name']} on {attack['node']}")
    
    if 'benign_traffic' in behaviors:
        logger.info(f"  Benign Traffic: {len(behaviors['benign_traffic'])}")
        for traffic in behaviors['benign_traffic']:
            logger.info(f"    - {traffic['name']} on {traffic['node']}")
    
    # Display data collection
    data_collection = config['data_collection']
    logger.info(f"\nData Collection:")
    
    if 'logs' in data_collection:
        logger.info(f"  Log Sources: {len(data_collection['logs'])}")
        for log in data_collection['logs']:
            logger.info(f"    - {log['source']}: {log['path']}")
    
    if 'network' in data_collection:
        logger.info(f"  Network Capture: {len(data_collection['network'])}")
    
    # Display hooks
    if 'hooks' in config:
        hooks = config['hooks']
        logger.info(f"\nHooks:")
        for hook_type, hook_list in hooks.items():
            logger.info(f"  {hook_type}: {len(hook_list)}")
    
    # Display output configuration
    if 'output' in config:
        output = config['output']
        logger.info(f"\nOutput:")
        logger.info(f"  Base Directory: {output.get('base_dir', 'N/A')}")
        logger.info(f"  Formats: {output.get('formats', [])}")
    
    logger.info("\n=== DRY RUN COMPLETED ===")
    return True


def run_scenario(config_path: str, dry_run_mode: bool = False) -> bool:
    """Run the scenario"""
    logger = logging.getLogger(__name__)
    
    # Load configuration
    config = load_config(config_path)
    if not config:
        return False
    
    # Perform dry run if requested
    if dry_run_mode:
        return dry_run(config)
    
    # Setup experiment directories
    logger.info("Setting up experiment directories...")
    experiment_name, full_experiment_name = setup_experiment_directories(config_path)
    
    # Add experiment info to environment for containers
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.environ['EXPERIMENT_NAME'] = experiment_name
    os.environ['FULL_EXPERIMENT_NAME'] = full_experiment_name
    os.environ['TIMESTAMP'] = timestamp
    
    try:
        # Initialize scenario manager with pre-loaded config
        logger.info("Initializing scenario manager...")
        resolved_config_path = resolve_config_path(config_path)
        scenario_manager = ScenarioManager(resolved_config_path, config)
        
        # Run the scenario
        logger.info("Starting scenario execution...")
        success = scenario_manager.run_scenario()
        
        if success:
            logger.info("Scenario completed successfully")
            
            # Get scenario summary
            summary = scenario_manager.get_scenario_summary()
            logger.info(f"Scenario Summary: {summary}")
            
        else:
            logger.error("Scenario execution failed")
            
        return success
        
    except Exception as e:
        logger.error(f"Error during scenario execution: {e}")
        return False


def setup_experiment_directories(config_path: str) -> tuple[str, str]:
    """
    Setup experiment directories using the hook
    
    Returns:
        tuple: (experiment_name, full_experiment_name)
    """
    import subprocess
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    try:
        # 运行目录设置hook
        result = subprocess.run([
            sys.executable, 
            "hooks/setup_experiment_directories.py", 
            config_path, 
            timestamp
        ], capture_output=True, text=True, check=True)
        
        # 解析输出
        experiment_name = None
        full_experiment_name = None
        
        for line in result.stdout.strip().split('\n'):
            if line.startswith('EXPERIMENT_NAME='):
                experiment_name = line.split('=', 1)[1]
            elif line.startswith('FULL_EXPERIMENT_NAME='):
                full_experiment_name = line.split('=', 1)[1]
        
        logging.info(f"✅ Experiment directories setup completed: {full_experiment_name}")
        return experiment_name, full_experiment_name
        
    except subprocess.CalledProcessError as e:
        logging.warning(f"Failed to setup experiment directories: {e}")
        # 回退到基本设置
        experiment_name = Path(config_path).stem
        full_experiment_name = f"{experiment_name}_{timestamp}"
        return experiment_name, full_experiment_name


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="CyberRange Scenario Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run modular scenario (default)
  python run_scenario.py
  
  # Run modular scenario explicitly
  python run_scenario.py --config scenarios/modular_demo.yaml
  
  # Run detailed examples
  python run_scenario.py --config scenarios/examples/detailed_basic_example.yaml
  python run_scenario.py --config scenarios/examples/detailed_complex_example.yaml
  
  # Dry run to validate configuration
  python run_scenario.py --config scenarios/modular_demo.yaml --dry-run
        """
    )
    
    parser.add_argument(
        '--config',
        default='scenarios/modular_demo.yaml',
        help='Path to scenario configuration file (default: scenarios/modular_demo.yaml)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Validate configuration without execution'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Set logging level (default: INFO)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='CyberRange 1.0.0'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.log_level)
    
    # Display startup information
    logger.info("=" * 60)
    logger.info("CyberRange Scenario Runner")
    logger.info("=" * 60)
    logger.info(f"Configuration: {args.config}")
    logger.info(f"Dry Run: {args.dry_run}")
    logger.info(f"Log Level: {args.log_level}")
    logger.info(f"Timestamp: {datetime.now()}")
    logger.info("=" * 60)
    
    # Run scenario
    success = run_scenario(args.config, args.dry_run)
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
