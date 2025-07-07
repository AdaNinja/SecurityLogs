#!/usr/bin/env python3
"""
Attack scenario startup script
"""

import os
import sys
import subprocess
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def check_dependencies():
    """Check dependencies"""
    logger.info("Checking dependencies...")
    
    # Check Docker
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            logger.info("✓ Docker installed")
        else:
            logger.error("✗ Docker not installed or unavailable")
            return False
    except FileNotFoundError:
        logger.error("✗ Docker not installed")
        return False
    
    # Check Docker Compose
    try:
        result = subprocess.run(["docker-compose", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            logger.info("✓ Docker Compose installed")
        else:
            logger.error("✗ Docker Compose not installed or unavailable")
            return False
    except FileNotFoundError:
        logger.error("✗ Docker Compose not installed")
        return False
    
    return True

def build_containers():
    """Build containers"""
    logger.info("Building Docker containers...")
    
    try:
        result = subprocess.run(
            ["docker-compose", "-f", "docker/docker-compose.yml", "build"],
            cwd=".",
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            logger.info("✓ Containers built successfully")
            return True
        else:
            logger.error(f"✗ Container build failed: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"✗ Error building containers: {e}")
        return False

def start_containers():
    """Start containers"""
    logger.info("Starting Docker containers...")
    
    try:
        result = subprocess.run(
            ["docker-compose", "-f", "docker/docker-compose.yml", "up", "-d"],
            cwd=".",
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            logger.info("✓ Containers started successfully")
            return True
        else:
            logger.error(f"✗ Container startup failed: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"✗ Error starting containers: {e}")
        return False

def wait_for_services():
    """Wait for services to be ready"""
    logger.info("Waiting for services to be ready...")
    
    import requests
    
    services = [
        ("MailHog Web UI", "http://localhost:8025"),
        ("Credential collection server", "http://localhost:9000/health")
    ]
    
    for service_name, url in services:
        logger.info(f"Checking {service_name}...")
        for i in range(30):  # Wait up to 30 seconds
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    logger.info(f"✓ {service_name} ready")
                    break
            except:
                if i == 29:
                    logger.warning(f"⚠ {service_name} may not be ready, but continuing")
                else:
                    time.sleep(1)

def run_scenario():
    """Run attack scenario"""
    logger.info("Running phishing attack scenario...")
    
    try:
        result = subprocess.run(
            [sys.executable, "run_scenario.py", "--config", "scenarios/phishing/scenario.yaml"],
            cwd=".",
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            logger.info("✓ Attack scenario executed successfully")
            logger.info("Output:")
            print(result.stdout)
        else:
            logger.error(f"✗ Attack scenario execution failed: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"✗ Error running scenario: {e}")
        return False
    
    return True

def show_results():
    """Show results"""
    logger.info("=== Attack Results ===")
    
    # Check credential collection
    try:
        import requests
        response = requests.get("http://localhost:9000/credentials", timeout=5)
        if response.status_code == 200:
            data = response.json()
            logger.info(f"Number of collected credentials: {data.get('count', 0)}")
            if data.get('credentials'):
                logger.info("Credential details:")
                for cred in data['credentials']:
                    logger.info(f"  - Time: {cred.get('timestamp')}")
                    logger.info(f"    IP: {cred.get('ip')}")
                    logger.info(f"    Credentials: {cred.get('credentials')}")
        else:
            logger.warning("Unable to get credential collection results")
    except Exception as e:
        logger.warning(f"Error checking results: {e}")

def main():
    """Main function"""
    logger.info("=== Phishing Attack Scenario Launcher ===")
    
    # 1. Check dependencies
    if not check_dependencies():
        logger.error("Dependency check failed, please install necessary tools")
        return
    
    # 2. Build containers
    if not build_containers():
        logger.error("Container build failed")
        return
    
    # 3. Start containers
    if not start_containers():
        logger.error("Container startup failed")
        return
    
    # 4. Wait for services to be ready
    wait_for_services()
    
    # 5. Run attack scenario
    if not run_scenario():
        logger.error("Attack scenario execution failed")
        return
    
    # 6. Show results
    show_results()
    
    logger.info("=== Attack Scenario Completed ===")
    logger.info("Tips:")
    logger.info("- View MailHog emails: http://localhost:8025")
    logger.info("- View credential collection: http://localhost:9000/credentials")
    logger.info("- Stop containers: docker-compose -f docker/docker-compose.yml down")

if __name__ == "__main__":
    main() 