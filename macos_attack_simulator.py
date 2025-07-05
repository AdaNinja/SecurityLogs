#!/usr/bin/env python3
"""
macOS Attack Simulator
Execute real attack activities locally on macOS and collect log data
"""

import os
import sys
import json
import time
import subprocess
import logging
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MacOSAttackSimulator:
    def __init__(self, scenarios_dir: str = "scenarios", output_dir: str = "macos_attack_logs"):
        self.scenarios_dir = scenarios_dir
        self.output_dir = output_dir
        self.current_scenario_dir = None  # Current scenario directory
        
        # Ensure output directory exists
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    def load_scenario_config(self, scenario_name: str) -> Dict[str, Any]:
        """Load attack scenario configuration"""
        config_path = os.path.join(self.scenarios_dir, scenario_name, "scenario.yaml")
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Scenario config not found: {config_path}")
        
        with open(config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def start_log_collection(self, scenario_name: str, variant_name: str) -> str:
        """Start log collection"""
        # Create directory structure organized by scenario and variant
        scenario_variant_dir = os.path.join(self.output_dir, scenario_name, variant_name)
        Path(scenario_variant_dir).mkdir(parents=True, exist_ok=True)
        
        # Create timestamp subdirectory
        timestamp = int(time.time())
        log_dir = os.path.join(scenario_variant_dir, f"run_{timestamp}")
        Path(log_dir).mkdir(parents=True, exist_ok=True)
        
        self.current_scenario_dir = scenario_variant_dir
        return log_dir

    def run_ssh_attack(self, variant_config: Dict[str, Any], log_dir: str) -> Dict[str, Any]:
        """Run SSH attack (simulation)"""
        logger.info("Running SSH attack simulation...")
        
        # Execute background activities first
        background_results = self._execute_background_activities(variant_config)
        
        # Create SSH attack script
        ssh_script = self._create_ssh_attack_script(variant_config)
        
        # Save script to macos_attack_results directory for reuse
        results_dir = "macos_attack_results"
        Path(results_dir).mkdir(parents=True, exist_ok=True)
        
        ssh_results_dir = os.path.join(results_dir, "ssh_attack")
        Path(ssh_results_dir).mkdir(parents=True, exist_ok=True)
        
        scenarios_script_path = os.path.join(ssh_results_dir, f"ssh_attack_{variant_config.get('name', 'unknown').lower().replace(' ', '_')}.sh")
        with open(scenarios_script_path, 'w') as f:
            f.write(ssh_script)
        os.chmod(scenarios_script_path, 0o755)
        
        # Also save to current scenario directory for this run
        script_path = os.path.join(self.current_scenario_dir, "ssh_attack.sh")
        with open(script_path, 'w') as f:
            f.write(ssh_script)
        os.chmod(script_path, 0o755)
        
        # Execute attack script
        start_time = datetime.now()
        result = subprocess.run([script_path], capture_output=True, text=True, timeout=30)
        end_time = datetime.now()
        
        return {
            'attack_type': 'ssh_brute_force',
            'variant': variant_config,
            'background_activities': background_results,
            'start_time': start_time.isoformat(),
            'logs': result.stdout.split('\n'),
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'end_time': end_time.isoformat()
        }

    def run_redis_attack(self, variant_config: Dict[str, Any], log_dir: str) -> Dict[str, Any]:
        """Run Redis attack (simulation)"""
        logger.info("Running Redis attack simulation...")
        
        # Execute background activities first
        background_results = self._execute_background_activities(variant_config)
        
        # Create Redis attack script
        redis_script = self._create_redis_attack_script(variant_config)
        
        # Save script to macos_attack_results directory for reuse
        results_dir = "macos_attack_results"
        Path(results_dir).mkdir(parents=True, exist_ok=True)
        
        redis_results_dir = os.path.join(results_dir, "redis_attack")
        Path(redis_results_dir).mkdir(parents=True, exist_ok=True)
        
        scenarios_script_path = os.path.join(redis_results_dir, f"redis_attack_{variant_config.get('name', 'unknown').lower().replace(' ', '_')}.sh")
        with open(scenarios_script_path, 'w') as f:
            f.write(redis_script)
        os.chmod(scenarios_script_path, 0o755)
        
        # Also save to current scenario directory for this run
        script_path = os.path.join(self.current_scenario_dir, "redis_attack.sh")
        with open(script_path, 'w') as f:
            f.write(redis_script)
        os.chmod(script_path, 0o755)
        
        # Execute attack script
        start_time = datetime.now()
        result = subprocess.run([script_path], capture_output=True, text=True, timeout=30)
        end_time = datetime.now()
        
        return {
            'attack_type': 'redis_unauthorized_access',
            'variant': variant_config,
            'background_activities': background_results,
            'start_time': start_time.isoformat(),
            'logs': result.stdout.split('\n'),
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'end_time': end_time.isoformat()
        }

    def run_macro_attack(self, variant_config: Dict[str, Any], log_dir: str) -> Dict[str, Any]:
        """Run macro attack (simulation)"""
        logger.info("Running macro attack simulation...")
        
        # Execute background activities first
        background_results = self._execute_background_activities(variant_config)
        
        # Get variant key from the calling context
        # We need to find the variant key that matches this config
        scenario_config = self.load_scenario_config('macro_attack')
        variant_key = None
        for key, variant in scenario_config.get('variants', {}).items():
            if variant == variant_config:
                variant_key = key
                break
        
        if not variant_key:
            logger.error("Could not determine variant key")
            raise ValueError("Variant key not found")
        
        # Determine which pre-generated script to use based on variant key
        script_name = f"macro_simulation_{variant_key}.py"
        script_path = os.path.join("scenarios", "macro_attack", script_name)
        
        if not os.path.exists(script_path):
            logger.error(f"Pre-generated script not found: {script_path}")
            raise FileNotFoundError(f"Script not found: {script_path}")
        
        logger.info(f"Executing pre-generated script: {script_path}")
        
        # Copy script to current scenario directory for this run
        current_script_path = os.path.join(self.current_scenario_dir, "macro_simulation.py")
        with open(script_path, 'r') as src, open(current_script_path, 'w') as dst:
            dst.write(src.read())
        
        # Execute attack script
        start_time = datetime.now()
        result = subprocess.run([sys.executable, current_script_path], capture_output=True, text=True, timeout=120)
        end_time = datetime.now()
        
        # Save results to macos_attack_results directory
        results_dir = "macos_attack_results"
        Path(results_dir).mkdir(parents=True, exist_ok=True)
        
        macro_results_dir = os.path.join(results_dir, "macro_attack")
        Path(macro_results_dir).mkdir(parents=True, exist_ok=True)
        
        # Save detailed results
        result_file = os.path.join(macro_results_dir, f"result_{variant_key}.json")
        result_data = {
            'attack_type': 'malicious_macro',
            'variant': variant_config,
            'background_activities': background_results,
            'start_time': start_time.isoformat(),
            'logs': result.stdout.split('\n'),
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'end_time': end_time.isoformat(),
            'execution_time': (end_time - start_time).total_seconds(),
            'script_used': script_path
        }
        
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(result_data, f, indent=2, ensure_ascii=False)
        
        return result_data

    def _execute_background_activities(self, variant_config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute background activities based on variant configuration"""
        background_results = {}
        background_activities = variant_config.get('background_activities', [])
        
        logger.info(f"Executing {len(background_activities)} background activities...")
        
        for activity in background_activities:
            activity_type = activity.get('type', 'unknown')
            intensity = activity.get('intensity', 'minimal')
            actions = activity.get('actions', [])
            duration = activity.get('duration', 30)
            
            logger.info(f"Executing {activity_type} activity (intensity: {intensity}, duration: {duration}s)")
            
            # Simulate background activity execution
            activity_result = {
                'type': activity_type,
                'intensity': intensity,
                'actions': actions,
                'duration': duration,
                'executed': True,
                'start_time': datetime.now().isoformat(),
                'end_time': None
            }
            
            # Simulate activity duration
            time.sleep(min(duration / 10, 2))  # Scale down for simulation
            
            activity_result['end_time'] = datetime.now().isoformat()
            background_results[activity_type] = activity_result
            
            logger.info(f"Completed {activity_type} activity")
        
        return background_results

    def _create_ssh_attack_script(self, variant_config: Dict[str, Any]) -> str:
        """Create SSH attack script"""
        return f"""#!/bin/bash
# SSH Brute Force Attack Simulation
echo "Starting SSH brute force attack simulation..."

# Simulate SSH connection attempts
for i in {{1..5}}; do
    echo "Attempt $i: Trying SSH connection..."
    sleep 1
done

echo "SSH attack simulation completed"
"""

    def _create_redis_attack_script(self, variant_config: Dict[str, Any]) -> str:
        """Create Redis attack script"""
        return f"""#!/bin/bash
# Redis Unauthorized Access Attack Simulation
echo "Starting Redis unauthorized access attack simulation..."

# Check if Redis is installed
if ! command -v redis-cli &> /dev/null; then
    echo "Redis not found, installing..."
    brew install redis
fi

# Try to connect to Redis
echo "Attempting Redis connection..."
redis-cli ping

echo "Redis attack simulation completed"
"""

    def _create_macro_attack_script(self, variant_config: Dict[str, Any]) -> str:
        """Create macro attack script based on variant configuration"""
        attack_config = variant_config.get('attack', {})
        stealth_level = attack_config.get('stealth_level', 'low')
        macro_actions = attack_config.get('macro_actions', [])
        execution_delay = attack_config.get('execution_delay', 0)
        obfuscation_level = attack_config.get('obfuscation_level', 'none')
        
        script_lines = [
            "#!/usr/bin/env python3",
            "# Malicious Macro Attack Simulation",
            "import subprocess",
            "import time",
            "import os",
            "import random",
            "",
            "def simulate_obfuscation(level):",
            "    if level == 'basic':",
            "        print('Using basic obfuscation...')",
            "        time.sleep(1)",
            "    elif level == 'advanced':",
            "        print('Using advanced obfuscation...')",
            "        time.sleep(3)",
            "        print('Anti-analysis checks passed')",
            "",
            "def execute_macro_actions(actions):",
            "    for action in actions:",
            "        if action == 'basic_command_execution':",
            "            print('Executing basic command...')",
            "            result = subprocess.check_output(['whoami']).decode().strip()",
            "            print(f'User: {result}')",
            "        elif action == 'file_creation':",
            "            print('Creating test file...')",
            "            with open('/tmp/macro_test.txt', 'w') as f:",
            "                f.write('Macro test file created')",
            "        elif action == 'encrypted_command_execution':",
            "            print('Executing encrypted command...')",
            "            result = subprocess.check_output(['hostname']).decode().strip()",
            "            print(f'Hostname: {result}')",
            "        elif action == 'registry_modification':",
            "            print('Simulating registry modification...')",
            "            print('Registry key modified')",
            "        elif action == 'network_connection':",
            "            print('Establishing network connection...')",
            "            print('Connection established')",
            "        elif action == 'polymorphic_payload_execution':",
            "            print('Executing polymorphic payload...')",
            "            result = subprocess.check_output(['ps', 'aux']).decode().strip()",
            "            print('Process list obtained')",
            "        elif action == 'anti_vm_checks':",
            "            print('Performing anti-VM checks...')",
            "            print('VM detection bypassed')",
            "        elif action == 'sandbox_evasion':",
            "            print('Evading sandbox detection...')",
            "            print('Sandbox evasion successful')",
            "        elif action == 'persistence_establishment':",
            "            print('Establishing persistence...')",
            "            print('Persistence mechanism installed')",
            "        elif action == 'lateral_movement_preparation':",
            "            print('Preparing for lateral movement...')",
            "            print('Lateral movement tools ready')",
            "        time.sleep(1)",
            "",
            "print('Macro executed')",
            "",
            "# Apply obfuscation based on level",
            f"simulate_obfuscation('{obfuscation_level}')",
            "",
            "# Execution delay based on stealth level",
            f"execution_delay = {execution_delay}",
            f"if execution_delay > 0:",
            f"    print(f'Delaying execution for {{execution_delay}} seconds...')",
            f"    time.sleep(execution_delay)",
            "",
            "print('Simulating malicious macro execution...')",
            "",
            "# Execute macro actions based on configuration",
            f"macro_actions = {macro_actions}",
            "execute_macro_actions(macro_actions)",
            "",
            "print('Macro simulation completed')"
        ]
        
        return "\n".join(script_lines)

    def run_scenario(self, scenario_name: str, variant_name: str) -> Dict[str, Any]:
        """Run specific scenario variant"""
        logger.info(f"Running scenario: {scenario_name} - {variant_name}")
        
        # Load scenario configuration
        scenario_config = self.load_scenario_config(scenario_name)
        
        # 获取指定变体配置
        variants = scenario_config.get('variants', {})
        if variant_name not in variants:
            raise ValueError(f"Variant '{variant_name}' not found in scenario '{scenario_name}'")
        variant_config = variants[variant_name]
        
        # Start log collection
        log_dir = self.start_log_collection(scenario_name, variant_name)
        
        # Run attack based on scenario type
        if scenario_name == 'ssh_attack':
            attack_result = self.run_ssh_attack(variant_config, log_dir)
        elif scenario_name == 'redis_attack':
            attack_result = self.run_redis_attack(variant_config, log_dir)
        elif scenario_name == 'macro_attack':
            attack_result = self.run_macro_attack(variant_config, log_dir)
        else:
            raise ValueError(f"Unknown scenario: {scenario_name}")
        
        # Prepare result
        result = {
            'scenario_name': scenario_name,
            'variant_name': variant_name,
            'attack_result': attack_result,
            'logging_config': {
                'start_time': datetime.now().isoformat(),
                'log_dir': log_dir,
                'scenario_dir': self.current_scenario_dir,
                'processes': [],
                'network_connections': [],
                'file_operations': []
            },
            'timestamp': datetime.now().isoformat()
        }
        
        # Save result to file
        result_file = os.path.join(self.current_scenario_dir, "attack_result.json")
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Attack simulation completed: {result_file}")
        return result

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='macOS Attack Simulator')
    parser.add_argument('--scenario', required=True, help='Scenario name')
    parser.add_argument('--variant', required=True, help='Variant name')
    
    args = parser.parse_args()
    
    simulator = MacOSAttackSimulator()
    result = simulator.run_scenario(args.scenario, args.variant)
    
    print(f"Attack simulation result: {result}")

if __name__ == "__main__":
    main() 