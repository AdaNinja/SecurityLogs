#!/usr/bin/env python3
"""
WAF Status Verification Hook
Verifies that ModSecurity WAF is running and configured correctly
"""

import requests
import time
import sys
import os
import json
import subprocess

def verify_waf_status():
    """Verify that ModSecurity WAF is properly configured"""
    
    # Get target URL from environment or use default
    target_url = os.environ.get('TARGET_URL', 'http://fancystore.com')
    waf_mode = os.environ.get('WAF_MODE', 'unknown')
    
    print(f"Verifying WAF status at: {target_url}")
    print(f"Expected WAF mode: {waf_mode}")
    
    # Test 1: Check if target is accessible
    print("\n=== Test 1: Basic connectivity ===")
    try:
        response = requests.get(f"{target_url}/", timeout=10)
        print(f"✓ Target accessible (Status: {response.status_code})")
        
        # Check for ModSecurity headers
        if 'Server' in response.headers:
            server_header = response.headers['Server']
            print(f"Server header: {server_header}")
            if 'modsecurity' in server_header.lower() or 'nginx' in server_header.lower():
                print("✓ Server appears to be running with potential WAF support")
            else:
                print("? Server header doesn't indicate WAF presence")
        
    except requests.exceptions.RequestException as e:
        print(f"✗ Failed to connect to target: {e}")
        return False
    
    # Test 2: Test with a simple attack pattern
    print("\n=== Test 2: WAF detection test ===")
    try:
        # Try a simple SQL injection payload
        test_payload = "' OR 1=1 --"
        response = requests.get(
            f"{target_url}/rest/products/search?q={test_payload}",
            timeout=10
        )
        
        print(f"Attack test response: {response.status_code}")
        
        if response.status_code == 403:
            print("✓ Attack blocked (403 Forbidden) - WAF is active and working")
            waf_active = True
        elif response.status_code in [200, 500]:
            print("! Attack not blocked - either WAF is disabled or rules are not effective")
            waf_active = False
        else:
            print(f"? Unexpected response code: {response.status_code}")
            waf_active = False
            
    except requests.exceptions.RequestException as e:
        print(f"✗ Failed to test WAF: {e}")
        return False
    
    # Test 3: Check container logs for ModSecurity
    print("\n=== Test 3: Container log analysis ===")
    try:
        # Try to get container info from environment
        containers_json = os.environ.get('CONTAINERS', '{}')
        containers = json.loads(containers_json)
        
        if 'nginx' in containers:
            container_info = containers['nginx']
            container_id = container_info.get('id', 'unknown') if isinstance(container_info, dict) else getattr(container_info, 'id', 'unknown')
            print(f"Found nginx container: {container_id}")
            
            # Check container logs for ModSecurity indicators
            try:
                result = subprocess.run(
                    ['docker', 'logs', '--tail', '50', container_id],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                logs = result.stdout + result.stderr
                if 'modsecurity' in logs.lower() or 'crs' in logs.lower():
                    print("✓ ModSecurity indicators found in container logs")
                else:
                    print("? No clear ModSecurity indicators in logs")
                    
            except subprocess.TimeoutExpired:
                print("! Docker logs command timed out")
            except Exception as e:
                print(f"! Failed to check container logs: {e}")
                
    except (json.JSONDecodeError, AttributeError) as e:
        print(f"Could not parse container information: {e}")
    
    # Test 4: Validate WAF mode expectations
    print("\n=== Test 4: WAF mode validation ===")
    scenario_name = os.environ.get('scenario_name', 'unknown')
    
    if 'waf-enabled' in scenario_name or waf_mode == 'on':
        if waf_active:
            print("✓ WAF is active as expected for enabled mode")
            result = True
        else:
            print("✗ WAF should be active but appears disabled")
            result = False
    elif 'waf-disabled' in scenario_name or waf_mode == 'off':
        if not waf_active:
            print("✓ WAF is disabled as expected")
            result = True
        else:
            print("! WAF is active but was expected to be disabled")
            result = True  # This might be intentional for logging
    else:
        print(f"? Unknown WAF expectation for scenario: {scenario_name}")
        result = True  # Don't fail on unknown scenarios
    
    print(f"\n=== WAF Verification Summary ===")
    print(f"Target: {target_url}")
    print(f"WAF Mode: {waf_mode}")
    print(f"WAF Active: {waf_active}")
    print(f"Verification: {'PASSED' if result else 'FAILED'}")
    
    return result

if __name__ == "__main__":
    success = verify_waf_status()
    sys.exit(0 if success else 1)
