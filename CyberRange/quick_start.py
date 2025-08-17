#!/usr/bin/env python3
"""
Quick Start Script for CyberRange
Provides easy one-click setup and execution for different scenarios
"""

import os
import sys
import subprocess
import argparse
import logging
from pathlib import Path


class QuickStart:
    """Quick start helper for CyberRange"""
    
    def __init__(self):
        self.setup_logging()
        self.logger = logging.getLogger(__name__)
        self.project_root = Path(__file__).parent.absolute()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def run_scenario(self, scenario_name: str, duration: int = None, 
                    attack_types: list = None, waf_mode: str = None) -> bool:
        """
        Run a scenario with specified parameters
        
        Args:
            scenario_name: Name of the scenario to run
            duration: Duration in seconds (optional)
            attack_types: List of attack types (optional)
            waf_mode: WAF mode (optional)
            
        Returns:
            bool: True if successful
        """
        try:
            # Step 1: Check environment
            self.logger.info("Step 1: Checking environment...")
            if not self.check_environment():
                return False
            
            # Step 2: Create or find configuration
            self.logger.info("Step 2: Preparing configuration...")
            config_file = self.prepare_configuration(
                scenario_name, duration, attack_types, waf_mode
            )
            
            if not config_file:
                return False
            
            # Step 3: Run scenario
            self.logger.info(f"Step 3: Running scenario {scenario_name}...")
            success = self.execute_scenario(config_file)
            
            if success:
                self.logger.info("✅ Scenario completed successfully!")
                self.show_results()
            else:
                self.logger.error("❌ Scenario execution failed")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error running scenario: {e}")
            return False
    
    def check_environment(self) -> bool:
        """Check if environment is ready"""
        try:
            cmd = [sys.executable, 'check_environment.py']
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
            return result.returncode == 0
        except Exception as e:
            self.logger.error(f"Environment check failed: {e}")
            return False
    
    def prepare_configuration(self, scenario_name: str, duration: int = None,
                            attack_types: list = None, waf_mode: str = None) -> str:
        """
        Prepare configuration file for the scenario
        
        Returns:
            str: Path to configuration file or None if failed
        """
        scenarios_dir = self.project_root / 'scenarios'
        
        # Try to find existing configuration
        possible_names = [
            f"{scenario_name}.yaml",
            f"{scenario_name}.yml",
            f"{scenario_name}_demo.yaml",
            f"{scenario_name}_demo.yml"
        ]
        
        for name in possible_names:
            config_path = scenarios_dir / name
            if config_path.exists():
                self.logger.info(f"Found existing configuration: {name}")
                return str(config_path)
        
        # Create dynamic configuration
        self.logger.info(f"Creating dynamic configuration for {scenario_name}")
        config_path = scenarios_dir / f"{scenario_name}_generated.yaml"
        
        config_content = self.generate_config_content(
            scenario_name, duration, attack_types, waf_mode
        )
        
        try:
            with open(config_path, 'w') as f:
                f.write(config_content)
            self.logger.info(f"Generated configuration: {config_path.name}")
            return str(config_path)
        except Exception as e:
            self.logger.error(f"Failed to create configuration: {e}")
            return None
    
    def generate_config_content(self, scenario_name: str, duration: int = None,
                              attack_types: list = None, waf_mode: str = None) -> str:
        """Generate YAML configuration content"""
        
        # Set defaults
        duration = duration or 300
        attack_types = attack_types or ['sql_injection', 'xss']
        waf_mode = waf_mode or 'off'
        
        config_content = f"""scenario:
  name: "{scenario_name}"
  description: "Auto-generated configuration for {scenario_name}"
  duration: {duration}
  random_seed: 12345
  attack_types: {attack_types}
  waf_mode: "{waf_mode}"
"""
        return config_content
    
    def execute_scenario(self, config_file: str) -> bool:
        """Execute the scenario"""
        try:
            cmd = [
                sys.executable, 'run_scenario.py',
                '--config', config_file,
                '--log-level', 'INFO'
            ]
            
            self.logger.info(f"Executing: {' '.join(cmd)}")
            
            # Run with real-time output
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT,
                text=True,
                cwd=self.project_root
            )
            
            # Print output in real-time
            for line in iter(process.stdout.readline, ''):
                print(line, end='')
            
            process.wait()
            return process.returncode == 0
            
        except Exception as e:
            self.logger.error(f"Failed to execute scenario: {e}")
            return False
    
    def show_results(self):
        """Show results after scenario completion"""
        output_dir = self.project_root / 'output'
        logs_dir = self.project_root / 'logs'
        
        self.logger.info("📊 Scenario Results:")
        
        # Show output files
        if output_dir.exists():
            csv_files = list(output_dir.glob('*.csv'))
            if csv_files:
                self.logger.info(f"   Generated {len(csv_files)} CSV files in output/")
                for csv_file in csv_files[:5]:  # Show first 5
                    self.logger.info(f"   - {csv_file.name}")
                if len(csv_files) > 5:
                    self.logger.info(f"   ... and {len(csv_files) - 5} more")
        
        # Show log files
        if logs_dir.exists():
            log_files = []
            for pattern in ['*.log', '*.pcap']:
                log_files.extend(logs_dir.rglob(pattern))
            
            if log_files:
                self.logger.info(f"   Collected {len(log_files)} log files in logs/")
        
        self.logger.info("💡 Next steps:")
        self.logger.info("   - Analyze CSV files in output/ directory")
        self.logger.info("   - Check raw logs in logs/ directory")
        self.logger.info("   - Use parsers/parse_logs.py for additional processing")
    
    def list_available_scenarios(self):
        """List available scenario configurations"""
        scenarios_dir = self.project_root / 'scenarios'
        
        if not scenarios_dir.exists():
            self.logger.warning("No scenarios directory found")
            return
        
        yaml_files = list(scenarios_dir.glob('*.yaml')) + list(scenarios_dir.glob('*.yml'))
        
        if not yaml_files:
            self.logger.info("No scenario configurations found")
            self.logger.info("Create one with: python quick_start.py --create-scenario <name>")
            return
        
        self.logger.info("Available scenarios:")
        for yaml_file in yaml_files:
            scenario_name = yaml_file.stem
            self.logger.info(f"  - {scenario_name}")
    
    def create_scenario_template(self, scenario_name: str, attack_types: list = None,
                               waf_mode: str = 'off', duration: int = 300):
        """Create a new scenario template"""
        try:
            from orchestrator.modular_adapter import create_simple_config_template
            
            scenarios_dir = self.project_root / 'scenarios'
            config_path = scenarios_dir / f"{scenario_name}.yaml"
            
            if config_path.exists():
                self.logger.warning(f"Scenario {scenario_name} already exists")
                return False
            
            create_simple_config_template(str(config_path), scenario_name)
            
            # Customize the template if parameters provided
            if attack_types or waf_mode != 'off' or duration != 300:
                self.customize_template(config_path, attack_types, waf_mode, duration)
            
            self.logger.info(f"✅ Created scenario template: {config_path.name}")
            self.logger.info(f"   Edit the file to customize your scenario")
            self.logger.info(f"   Run with: python quick_start.py --run {scenario_name}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create scenario template: {e}")
            return False
    
    def customize_template(self, config_path: Path, attack_types: list = None,
                          waf_mode: str = None, duration: int = None):
        """Customize a scenario template"""
        try:
            import yaml
            
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            if attack_types:
                config['scenario']['attack_types'] = attack_types
            if waf_mode:
                config['scenario']['waf_mode'] = waf_mode
            if duration:
                config['scenario']['duration'] = duration
            
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)
                
        except Exception as e:
            self.logger.warning(f"Failed to customize template: {e}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Quick Start for CyberRange",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List available scenarios
  python quick_start.py --list
  
  # Run existing scenario
  python quick_start.py --run waf_off_demo
  
  # Create and run custom scenario
  python quick_start.py --run my_test --duration 60 --attacks sql_injection xss
  
  # Create scenario template
  python quick_start.py --create-scenario my_scenario --attacks sql_injection --waf-mode on
  
  # Quick demo
  python quick_start.py --demo
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    
    group.add_argument(
        '--run',
        type=str,
        help='Run a scenario (existing or auto-generated)'
    )
    
    group.add_argument(
        '--list',
        action='store_true',
        help='List available scenarios'
    )
    
    group.add_argument(
        '--create-scenario',
        type=str,
        help='Create a new scenario template'
    )
    
    group.add_argument(
        '--demo',
        action='store_true',
        help='Run a quick demo scenario'
    )
    
    # Optional parameters for scenarios
    parser.add_argument(
        '--duration',
        type=int,
        default=300,
        help='Scenario duration in seconds (default: 300)'
    )
    
    parser.add_argument(
        '--attacks',
        nargs='+',
        choices=['sql_injection', 'xss', 'directory_traversal', 'command_injection', 'authentication_bypass'],
        default=['sql_injection', 'xss'],
        help='Attack types to include (default: sql_injection xss)'
    )
    
    parser.add_argument(
        '--waf-mode',
        choices=['on', 'off', 'auto'],
        default='off',
        help='WAF mode (default: off)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    quick_start = QuickStart()
    
    try:
        if args.list:
            quick_start.list_available_scenarios()
            
        elif args.create_scenario:
            success = quick_start.create_scenario_template(
                args.create_scenario, args.attacks, args.waf_mode, args.duration
            )
            sys.exit(0 if success else 1)
            
        elif args.demo:
            # Run a quick demo
            quick_start.logger.info("🚀 Running CyberRange Demo...")
            success = quick_start.run_scenario(
                'demo', duration=60, attack_types=['sql_injection'], waf_mode='off'
            )
            sys.exit(0 if success else 1)
            
        elif args.run:
            success = quick_start.run_scenario(
                args.run, args.duration, args.attacks, args.waf_mode
            )
            sys.exit(0 if success else 1)
            
    except KeyboardInterrupt:
        quick_start.logger.info("\n👋 Interrupted by user")
        sys.exit(1)
    except Exception as e:
        quick_start.logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
