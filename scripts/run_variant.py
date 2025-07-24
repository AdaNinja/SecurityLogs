#!/usr/bin/env python3
"""
Automated Variant Runner
Run security experiments for different variants automatically
"""

import os
import sys
import subprocess
import argparse
import json
import time
import signal
from datetime import datetime
from pathlib import Path

VARIANT_CONFIGS = {
    "stealthy": {
        "variant_id": "lowscan_stealthy",
        "description": "Stealthy SQL injection attacks with long delays and DNS reconnaissance",
        "attack_delay": "5-10",
        "dns_attack_config": {
            "enabled": True,
            "phases": ["reconnaissance", "brute_force"],
            "intensity": "low",
            "delay_between_queries": "2-5",
            "subdomain_wordlist_size": 40
        }
    },
    "moderate": {
        "variant_id": "lowscan_moderate", 
        "description": "Moderate SQL injection attacks with medium delays and DNS tunneling",
        "attack_delay": "3-6",
        "dns_attack_config": {
            "enabled": True,
            "phases": ["reconnaissance", "brute_force", "cache_poisoning", "tunneling"],
            "intensity": "medium",
            "delay_between_queries": "1-3",
            "subdomain_wordlist_size": 60
        }
    },
    "aggressive": {
        "variant_id": "lowscan_aggressive",
        "description": "Aggressive SQL injection attacks with short delays and full DNS attack suite",
        "attack_delay": "1-3",
        "dns_attack_config": {
            "enabled": True,
            "phases": ["reconnaissance", "brute_force", "cache_poisoning", "amplification", "tunneling", "cc_communication"],
            "intensity": "high",
            "delay_between_queries": "0.5-1",
            "subdomain_wordlist_size": 80
        }
    }
}

# Global variable to store benign traffic PID
benign_traffic_pid = None

def signal_handler(signum, frame):
    """Handle cleanup on interrupt"""
    print("\nReceived interrupt signal, cleaning up...")
    cleanup_benign_traffic()
    sys.exit(1)

def cleanup_benign_traffic():
    """Clean up benign traffic processes"""
    global benign_traffic_pid
    if benign_traffic_pid:
        try:
            os.kill(benign_traffic_pid, signal.SIGTERM)
            print(f"Terminated benign traffic process {benign_traffic_pid}")
        except ProcessLookupError:
            pass
        benign_traffic_pid = None

def run_docker_compose(scenario_dir, command):
    """Run docker-compose command"""
    try:
        # Get the correct scenario directory path
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        scenario_path = os.path.join(project_root, scenario_dir)
        
        # Use docker-compose v1 syntax (docker-compose command)
        cmd_parts = command.split()
        compose_cmd = ["docker-compose", "-f", os.path.join(scenario_path, "docker-compose.yml"), "-f", os.path.join(scenario_path, "docker-compose.override.yml")] + cmd_parts
        
        result = subprocess.run(
            compose_cmd,
            cwd=scenario_path,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode != 0:
            print(f"Docker-compose {command} failed: {result.stderr}")
            return False
        
        return True
    except subprocess.TimeoutExpired:
        print(f"Docker-compose {command} timed out")
        return False
    except Exception as e:
        print(f"Error running docker-compose {command}: {e}")
        return False

def wait_for_services():
    """Wait for services to be ready"""
    print("Waiting for services to be ready...")
    
    # Wait for webapp
    for i in range(30):
        try:
            result = subprocess.run(
                ["curl", "-f", "http://localhost:8081"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                print("Webapp is ready")
                break
        except:
            pass
        time.sleep(2)
    else:
        print("Warning: Webapp may not be ready")
    
    return True

def run_attack_experiment(variant_id, interleaved=False, benign_mix="HTTP:0.6,DNS:0.3,SMTP:0.1", benign_duration=300):
    """Run the attack experiment"""
    print(f"Running attack experiment for {variant_id}")
    
    if interleaved:
        print("Starting interleaved attack with benign traffic...")
        # Start benign traffic in background
        cmd = f"python3 scripts/benign_traffic_generator.py --mix {benign_mix} --duration {benign_duration}"
        try:
            process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            global benign_traffic_pid
            benign_traffic_pid = process.pid
            print(f"Started benign traffic with PID {benign_traffic_pid}")
        except Exception as e:
            print(f"Failed to start benign traffic: {e}")
    
    # Run the attack
    try:
        result = subprocess.run(
            ["docker", "exec", "securitylogs-attacker", "python3", "/opt/scripts/attack_modules/container_attack.py"],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode == 0:
            print("Attack experiment completed successfully")
            return True
        else:
            print(f"Attack experiment failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("Attack experiment timed out")
        return False
    except Exception as e:
        print(f"Error running attack experiment: {e}")
        return False

def generate_override_config(variant_name):
    """Generate docker-compose.override.yml for the variant"""
    if variant_name not in VARIANT_CONFIGS:
        raise ValueError(f"Unknown variant: {variant_name}")
    
    config = VARIANT_CONFIGS[variant_name]
    variant_id = config["variant_id"]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    override_content = f"""version: '3.8'
services:
  webapp:
    ports:
      - "8081:80"
    environment:
      - VARIANT_ID={variant_id}
      - EXPERIMENT_TIMESTAMP={timestamp}
    volumes:
      # Variant-specific data collection structure (simplified)
      - ../../data/logs/{variant_id}/web:/var/log/nginx
      - ../../data/logs/{variant_id}/system:/var/log/system
      - ../../data/logs/{variant_id}/attacks:/opt/output

  attacker:
    environment:
      - VARIANT_ID={variant_id}
      - EXPERIMENT_TIMESTAMP={timestamp}
    volumes:
      # Variant-specific output and logs (simplified)
      - ../../data/logs/{variant_id}/attacks:/opt/output
      - ../../data/logs/{variant_id}/system:/opt/logs

  tcpdump:
    environment:
      - VARIANT_ID={variant_id}
      - EXPERIMENT_TIMESTAMP={timestamp}
    volumes:
      # Variant-specific PCAP and logs (simplified)
      - ../../data/logs/{variant_id}/pcap:/pcaps
      - ../../data/logs/{variant_id}/system:/logs

networks:
  attacknet:
    name: "{variant_id}_net"
"""
    
    return override_content

def create_variant_directories(variant_id, skip_cleanup=False):
    """Create necessary directories for the variant"""
    variant_logs_dir = f"data/logs/{variant_id}"
    variant_raw_dir = f"data/raw/{variant_id}"
    
    if not skip_cleanup:
        # First, clear existing data if it exists
        if os.path.exists(variant_logs_dir):
            print(f"Clearing existing logs data for variant: {variant_id}")
            os.system(f"sudo rm -rf {variant_logs_dir}")
        
        if os.path.exists(variant_raw_dir):
            print(f"Clearing existing raw data for variant: {variant_id}")
            os.system(f"sudo rm -rf {variant_raw_dir}")
    else:
        print(f"Skipping cleanup for variant: {variant_id}")
    
    # New simplified directory structure
    directories = [
        f"data/logs/{variant_id}",
        f"data/logs/{variant_id}/attacks",  # Attack outputs
        f"data/logs/{variant_id}/web",      # Web server logs
        f"data/logs/{variant_id}/system",   # System logs
        f"data/logs/{variant_id}/proxy",    # Proxy logs
        f"data/logs/{variant_id}/pcap",     # Network captures
        f"data/raw/{variant_id}",
        f"data/raw/{variant_id}/pcap_analysis"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        # Set permissions
        os.system(f"sudo chown -R 1000:1000 {directory}")
        os.system(f"sudo chmod -R 777 {directory}")
    
    print(f"Created directories for variant: {variant_id}")

def generate_initial_data(variant_id):
    """Generate initial data files for the variant"""
    print(f"Generating initial data for variant: {variant_id}")
    
    try:
        # Run the log generator script
        cmd = f"python3 data_processing/log_generator.py --variant-id {variant_id} --dns-count 50 --http-count 50"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print("✅ Initial data generation completed successfully")
            return True
        else:
            print(f"❌ Initial data generation failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Initial data generation timed out")
        return False
    except Exception as e:
        print(f"❌ Error generating initial data: {e}")
        return False

def write_override_file(content, scenario_dir):
    """Write docker-compose.override.yml file"""
    # Get the correct path relative to the project root
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    override_file = os.path.join(project_root, scenario_dir, "docker-compose.override.yml")
    with open(override_file, 'w') as f:
        f.write(content)
    print(f"Written override config to {override_file}")

def run_etl_processing(variant_id):
    """Run ETL processing for the variant"""
    print(f"Running ETL processing for {variant_id}")
    
    # Get the correct path for the ETL script
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    etl_script = os.path.join(project_root, "scripts", "data_processing", "run_all_etl.py")
    cmd = f"python3 {etl_script} --variant-id {variant_id}"
    print(f"Executing: {cmd}")
    
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    print(f"ETL return code: {result.returncode}")
    print(f"ETL stdout length: {len(result.stdout)}")
    print(f"ETL stderr length: {len(result.stderr)}")
    
    if result.returncode != 0:
        print(f"ETL processing failed: {result.stderr}")
        return False
    
    print("ETL processing completed successfully")
    return True

def run_variant(variant_name, scenario_dir="scenarios/low-and-slow-sqli", skip_etl=False, 
                interleaved=False, benign_mix="HTTP:0.6,DNS:0.3,SMTP:0.1", benign_duration=300, skip_cleanup=False):
    """Run complete experiment for a variant"""
    print(f"Starting experiment for variant: {variant_name}")
    if interleaved:
        print("Mode: Interleaved (attack + benign traffic)")
    else:
        print("Mode: Attack only")
    print("=" * 60)
    print("Experiment timeout: 10 minutes")
    print("=" * 60)
    
    # Set up signal handler for cleanup
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Set overall experiment timeout (10 minutes)
    experiment_start_time = time.time()
    experiment_timeout = 600  # 10 minutes
    
    try:
        # 1. Generate override configuration
        override_content = generate_override_config(variant_name)
        variant_id = VARIANT_CONFIGS[variant_name]["variant_id"]
        
        # 2. Create directories
        create_variant_directories(variant_id, skip_cleanup)
        
        # 3. Generate initial data files
        if not generate_initial_data(variant_id):
            print("Warning: Initial data generation failed, but continuing...")
        
        # 4. Write override file
        write_override_file(override_content, scenario_dir)
        
        # 5. Stop existing containers
        print("Stopping existing containers...")
        run_docker_compose(scenario_dir, "down")
        
        # 6. Start containers with new config
        print("Starting containers with new configuration...")
        if not run_docker_compose(scenario_dir, "up -d"):
            return False
        
        # 7. Wait for services
        if not wait_for_services():
            return False
        
        # 8. Run attack experiment
        if not run_attack_experiment(variant_id, interleaved, benign_mix, benign_duration):
            return False
        
        # 9. Run ETL processing (optional)
        if not skip_etl:
            print("Starting ETL processing...")
            etl_result = run_etl_processing(variant_id)
            print(f"ETL processing result: {etl_result}")
            if not etl_result:
                print("ETL processing failed, but continuing...")
                # Don't fail the entire experiment if ETL fails
                # return False
        else:
            print("Skipping ETL processing")
        
        # Check overall experiment timeout
        experiment_elapsed = time.time() - experiment_start_time
        if experiment_elapsed > experiment_timeout:
            print(f"Experiment exceeded {experiment_timeout//60} minute timeout")
            print(f"   Elapsed time: {experiment_elapsed//60:.1f} minutes")
            return False
        
        print(f"Experiment for {variant_name} completed successfully!")
        print(f"Total time: {experiment_elapsed//60:.1f} minutes")
        return True
        
    except Exception as e:
        print(f"Experiment failed: {e}")
        if interleaved:
            cleanup_benign_traffic()
        return False

def main():
    parser = argparse.ArgumentParser(description="Run security experiment for a variant")
    parser.add_argument("variant", choices=list(VARIANT_CONFIGS.keys()), 
                       help="Variant to run (stealthy, moderate, aggressive)")
    parser.add_argument("--scenario-dir", default="scenarios/low-and-slow-sqli",
                       help="Scenario directory path")
    parser.add_argument("--skip-etl", action="store_true",
                       help="Skip ETL processing")
    parser.add_argument("--skip-cleanup", action="store_true",
                       help="Skip cleanup of existing data (faster startup)")
    parser.add_argument("--interleaved", action="store_true",
                       help="Run with interleaved benign traffic")
    parser.add_argument("--benign-mix", default="HTTP:0.6,DNS:0.3,SMTP:0.1",
                       help="Benign traffic protocol mix (e.g., HTTP:0.6,DNS:0.3,SMTP:0.1)")
    parser.add_argument("--benign-duration", type=int, default=300,
                       help="Benign traffic duration in seconds")
    
    args = parser.parse_args()
    
    success = run_variant(
        args.variant, 
        args.scenario_dir, 
        args.skip_etl,
        args.interleaved,
        args.benign_mix,
        args.benign_duration,
        args.skip_cleanup
    )
    
    if success:
        print(f"\nVariant {args.variant} experiment completed successfully!")
        sys.exit(0)
    else:
        print(f"\nVariant {args.variant} experiment failed!")
        sys.exit(1)

if __name__ == "__main__":
    main() 