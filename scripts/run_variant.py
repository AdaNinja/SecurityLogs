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
        "description": "Stealthy SQL injection attacks with long delays",
        "attack_delay": "5-10"
    },
    "moderate": {
        "variant_id": "lowscan_moderate", 
        "description": "Moderate SQL injection attacks with medium delays",
        "attack_delay": "3-6"
    },
    "aggressive": {
        "variant_id": "lowscan_aggressive",
        "description": "Aggressive SQL injection attacks with short delays", 
        "attack_delay": "1-3"
    }
}

# Global variable to store benign traffic PID
benign_traffic_pid = None

def signal_handler(signum, frame):
    """Handle cleanup on interrupt"""
    print("\n🛑 Received interrupt signal, cleaning up...")
    cleanup_benign_traffic()
    sys.exit(1)

def cleanup_benign_traffic():
    """Clean up benign traffic processes"""
    global benign_traffic_pid
    if benign_traffic_pid:
        try:
            print(f"🛑 Stopping benign traffic (PID: {benign_traffic_pid})...")
            subprocess.run(f"kill {benign_traffic_pid}", shell=True)
            time.sleep(2)
        except:
            pass
    
    # Also stop any remaining benign traffic processes in webapp container
    try:
        subprocess.run("docker exec securitylogs-webapp pkill -f 'run_benign.sh'", shell=True)
        subprocess.run("docker exec securitylogs-webapp pkill -f 'http_traffic.sh'", shell=True)
        subprocess.run("docker exec securitylogs-webapp pkill -f 'dns_traffic.sh'", shell=True)
        subprocess.run("docker exec securitylogs-webapp pkill -f 'smtp_traffic.sh'", shell=True)
    except:
        pass
    
    print("✅ Benign traffic cleanup completed")

def start_benign_traffic(protocol_mix="HTTP:0.6,DNS:0.3,SMTP:0.1", duration=300):
    """Start benign traffic simulation"""
    global benign_traffic_pid
    
    print(f"🌐 Starting benign traffic simulation...")
    print(f"   Protocol mix: {protocol_mix}")
    print(f"   Duration: {duration} seconds")
    
    # Simple benign traffic using curl commands
    try:
        # Create a simple benign traffic script
        benign_script = f"""#!/bin/bash
# Simple benign traffic generator
echo "Starting simple benign traffic for {duration} seconds"
for i in $(seq 1 {duration//10}); do
    curl -s -o /dev/null http://localhost/ >/dev/null 2>&1 &
    curl -s -o /dev/null http://localhost/index.html >/dev/null 2>&1 &
    curl -s -o /dev/null http://localhost/about >/dev/null 2>&1 &
    sleep 10
done
echo "Benign traffic completed"
"""
        
        # Write script to a temporary file
        script_path = "/tmp/benign_traffic.sh"
        with open(script_path, "w") as f:
            f.write(benign_script)
        
        # Copy script to container and execute
        subprocess.run(f"docker cp {script_path} securitylogs-webapp:/tmp/benign_traffic.sh", shell=True)
        subprocess.run("docker exec securitylogs-webapp chmod +x /tmp/benign_traffic.sh", shell=True)
        
        # Start benign traffic in background
        cmd = "docker exec securitylogs-webapp bash /tmp/benign_traffic.sh"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        benign_traffic_pid = process.pid
        print(f"✅ Benign traffic started (PID: {benign_traffic_pid})")
        
        # Wait a bit for traffic to establish (reduced to 2 seconds)
        print("⏳ Waiting for benign traffic to establish (2 seconds)...")
        time.sleep(2)
        
        # Check if process is still running
        if process.poll() is None:
            print("✅ Benign traffic is running successfully")
            return True
        else:
            stdout, stderr = process.communicate()
            print(f"⚠️ Benign traffic process exited early")
            print(f"   stdout: {stdout.decode()}")
            print(f"   stderr: {stderr.decode()}")
            return False
            
    except Exception as e:
        print(f"❌ Failed to start benign traffic: {e}")
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
      # Variant-specific data collection structure
      - ../../data/logs/{variant_id}:/var/log
      - ../../data/logs/{variant_id}/pcap:/data/raw
      - ../../data/logs/{variant_id}/output:/opt/output

  attacker:
    environment:
      - VARIANT_ID={variant_id}
      - EXPERIMENT_TIMESTAMP={timestamp}
    volumes:
      # Variant-specific output and logs
      - ../../data/logs/{variant_id}/output:/opt/output
      - ../../data/logs/{variant_id}/logs:/opt/logs

  tcpdump:
    environment:
      - VARIANT_ID={variant_id}
      - EXPERIMENT_TIMESTAMP={timestamp}
    volumes:
      # Variant-specific PCAP and logs
      - ../../data/logs/{variant_id}/pcap:/pcaps
      - ../../data/logs/{variant_id}/logs:/logs

  log-aggregator:
    environment:
      - VARIANT_ID={variant_id}
      - EXPERIMENT_TIMESTAMP={timestamp}
    volumes:
      # Variant-specific logs and output
      - ../../data/logs/{variant_id}:/logs
      - ../../data/logs/{variant_id}/output:/output

networks:
  attacknet:
    name: "{variant_id}_net"
"""
    
    return override_content

def create_variant_directories(variant_id):
    """Create necessary directories for the variant"""
    # First, clear existing data if it exists
    variant_logs_dir = f"data/logs/{variant_id}"
    variant_raw_dir = f"data/raw/{variant_id}"
    
    if os.path.exists(variant_logs_dir):
        print(f"🗑️  Clearing existing logs data for variant: {variant_id}")
        os.system(f"sudo rm -rf {variant_logs_dir}")
    
    if os.path.exists(variant_raw_dir):
        print(f"🗑️  Clearing existing raw data for variant: {variant_id}")
        os.system(f"sudo rm -rf {variant_raw_dir}")
    
    directories = [
        f"data/logs/{variant_id}",
        f"data/logs/{variant_id}/output", 
        f"data/logs/{variant_id}/logs",
        f"data/logs/{variant_id}/pcap",
        f"data/raw/{variant_id}",
        f"data/raw/{variant_id}/pcap_analysis"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        # Set permissions
        os.system(f"sudo chown -R 1000:1000 {directory}")
        os.system(f"sudo chmod -R 777 {directory}")
    
    print(f"✅ Created directories for variant: {variant_id}")

def write_override_file(override_content, scenario_dir):
    """Write override configuration to file"""
    override_file = os.path.join(scenario_dir, "docker-compose.override.yml")
    with open(override_file, 'w') as f:
        f.write(override_content)
    print(f"✅ Generated override config: {override_file}")

def run_docker_compose(scenario_dir, action="up -d"):
    """Run docker-compose commands"""
    cmd = f"docker-compose -f {scenario_dir}/docker-compose.yml -f {scenario_dir}/docker-compose.override.yml {action}"
    print(f"🔄 Running: {cmd}")
    
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"❌ Docker-compose failed: {result.stderr}")
        return False
    
    print(f"✅ Docker-compose {action} completed successfully")
    return True

def wait_for_services():
    """Wait for services to be ready"""
    print("⏳ Waiting for services to be ready...")
    import time
    time.sleep(15)  # Reduced from 30 to 15 seconds
    
    # Check if webapp is healthy (reduced attempts)
    for i in range(5):  # Reduced from 10 to 5 attempts
        result = subprocess.run("docker ps | grep securitylogs-webapp | grep healthy", shell=True)
        if result.returncode == 0:
            print("✅ Webapp is healthy")
            return True
        print(f"⏳ Waiting for webapp health check... ({i+1}/5)")
        time.sleep(5)  # Reduced from 10 to 5 seconds
    
    print("⚠️  Webapp health check timeout, continuing anyway...")
    return True

def run_attack_experiment(variant_id, interleaved=False, benign_mix="HTTP:0.6,DNS:0.3,SMTP:0.1", benign_duration=300):
    """Run the attack experiment"""
    print(f"🚀 Starting attack experiment for {variant_id}")
    
    if interleaved:
        print("🔄 Running in interleaved mode (attack + benign traffic)")
        
        # Start benign traffic first with better error handling
        print("🔄 Attempting to start benign traffic...")
        if not start_benign_traffic(benign_mix, benign_duration):
            print("⚠️ Benign traffic failed to start, continuing with attack only")
            print("   This is normal and won't affect the attack experiment")
        else:
            print("✅ Benign traffic started successfully")
    
    try:
        # Run attack script with timeout for faster execution
        cmd = f"docker exec securitylogs-attacker python3 /opt/scripts/attack_modules/container_attack.py"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)  # 5分钟超时
        
        print("✅ Attack experiment completed successfully")
        print(result.stdout)
        
        if result.returncode != 0:
            print(f"❌ Attack experiment failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("⏰ Attack experiment timed out after 5 minutes")
        print("🛑 Forcing cleanup and continuing...")
        if interleaved:
            cleanup_benign_traffic()
        return False
        
    except Exception as e:
        print(f"❌ Attack experiment failed: {e}")
        if interleaved:
            cleanup_benign_traffic()
        return False
    
    # If running in interleaved mode, wait for benign traffic to complete
    if interleaved and benign_traffic_pid:
        print("⏳ Waiting for benign traffic to complete...")
        try:
            # Wait with shorter timeout to avoid getting stuck (max 2 minutes)
            subprocess.run(f"wait {benign_traffic_pid}", shell=True, timeout=min(benign_duration, 120))
        except subprocess.TimeoutExpired:
            print("⚠️ Benign traffic timeout, forcing cleanup")
        finally:
            cleanup_benign_traffic()
    
    return True

def run_etl_processing(variant_id):
    """Run ETL processing for the variant"""
    print(f"📊 Running ETL processing for {variant_id}")
    
    cmd = f"python3 scripts/data_processing/run_all_etl.py --variant-id {variant_id}"
    print(f"🔄 Executing: {cmd}")
    
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    print(f"📊 ETL return code: {result.returncode}")
    print(f"📊 ETL stdout length: {len(result.stdout)}")
    print(f"📊 ETL stderr length: {len(result.stderr)}")
    
    if result.returncode != 0:
        print(f"❌ ETL processing failed: {result.stderr}")
        return False
    
    print("✅ ETL processing completed successfully")
    print(result.stdout)
    return True

def run_variant(variant_name, scenario_dir="scenarios/low-and-slow-sqli", skip_etl=False, 
                interleaved=False, benign_mix="HTTP:0.6,DNS:0.3,SMTP:0.1", benign_duration=300):
    """Run complete experiment for a variant"""
    print(f"🎯 Starting experiment for variant: {variant_name}")
    if interleaved:
        print("🔄 Mode: Interleaved (attack + benign traffic)")
    else:
        print("🎯 Mode: Attack only")
    print("=" * 60)
    print("⏰ Experiment timeout: 10 minutes")
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
        create_variant_directories(variant_id)
        
        # 3. Write override file
        write_override_file(override_content, scenario_dir)
        
        # 4. Stop existing containers
        print("🛑 Stopping existing containers...")
        run_docker_compose(scenario_dir, "down")
        
        # 5. Start containers with new config
        print("🚀 Starting containers with new configuration...")
        if not run_docker_compose(scenario_dir, "up -d"):
            return False
        
        # 6. Wait for services
        if not wait_for_services():
            return False
        
        # 7. Run attack experiment
        if not run_attack_experiment(variant_id, interleaved, benign_mix, benign_duration):
            return False
        
        # 8. Run ETL processing (optional)
        if not skip_etl:
            print("🔄 Starting ETL processing...")
            etl_result = run_etl_processing(variant_id)
            print(f"📊 ETL processing result: {etl_result}")
            if not etl_result:
                print("❌ ETL processing failed, but continuing...")
                # Don't fail the entire experiment if ETL fails
                # return False
        else:
            print("⏭️ Skipping ETL processing")
        
        # Check overall experiment timeout
        experiment_elapsed = time.time() - experiment_start_time
        if experiment_elapsed > experiment_timeout:
            print(f"⏰ Experiment exceeded {experiment_timeout//60} minute timeout")
            print(f"   Elapsed time: {experiment_elapsed//60:.1f} minutes")
            return False
        
        print(f"🎉 Experiment for {variant_name} completed successfully!")
        print(f"⏱️ Total time: {experiment_elapsed//60:.1f} minutes")
        return True
        
    except Exception as e:
        print(f"❌ Experiment failed: {e}")
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
        args.benign_duration
    )
    
    if success:
        print(f"\n✅ Variant {args.variant} experiment completed successfully!")
        sys.exit(0)
    else:
        print(f"\n❌ Variant {args.variant} experiment failed!")
        sys.exit(1)

if __name__ == "__main__":
    main() 