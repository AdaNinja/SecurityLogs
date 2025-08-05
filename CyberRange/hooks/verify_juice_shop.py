#!/usr/bin/env python3
"""
Juice Shop Service Verification Hook
"""

import requests
import time
import sys
import os
import json

def verify_juice_shop():
    """Verify that Juice Shop is running and accessible"""
    
    # Get target URL from environment or use default
    target_url = os.environ.get('TARGET_URL', 'http://juice_shop:3000')
    
    # Try to get container info from environment
    containers_json = os.environ.get('CONTAINERS', '{}')
    try:
        containers = json.loads(containers_json)
        if 'juice-shop' in containers:
            container_info = containers['juice-shop']
            # Handle both dictionary and object access
            if isinstance(container_info, dict):
                container_id = container_info.get('id', 'unknown')
            else:
                container_id = getattr(container_info, 'id', 'unknown')
            print(f"Found juice-shop container: {container_id}")
    except (json.JSONDecodeError, AttributeError) as e:
        print(f"Could not parse container information: {e}")
    
    print(f"Verifying Juice Shop at: {target_url}")
    
    # Try to connect to Juice Shop
    max_retries = 10
    retry_interval = 5
    
    for attempt in range(max_retries):
        try:
            response = requests.get(f"{target_url}/", timeout=10)
            
            if response.status_code == 200:
                print(f"Juice Shop is running and accessible (Status: {response.status_code})")
                return True
            else:
                print(f"Juice Shop responded with status: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print(f"Attempt {attempt + 1}/{max_retries}: Failed to connect to Juice Shop: {e}")
            
        if attempt < max_retries - 1:
            print(f"Retrying in {retry_interval} seconds...")
            time.sleep(retry_interval)
    
    print("Failed to verify Juice Shop after all attempts")
    return False

if __name__ == "__main__":
    success = verify_juice_shop()
    sys.exit(0 if success else 1) 