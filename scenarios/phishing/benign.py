#!/usr/bin/env python3
"""
Benign behavior script - Simulate normal network activities
"""

import time
import requests
import random
import logging
from logger_utils import log_attack_event

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run(params):
    """
    Execute benign network activities
    
    Args:
        params: Scenario parameters dictionary
    """
    logger.info("Starting benign network activities...")
    
    benign_sites = params.get("benign_sites", [
        "http://example.com",
        "http://example.org",
        "http://httpbin.org"
    ])
    
    # Simulate normal web browsing behavior
    for i in range(5):
        try:
            # Randomly select a website
            site = random.choice(benign_sites)
            logger.info(f"Accessing website: {site}")
            
            # Send HTTP request
            response = requests.get(site, timeout=10)
            logger.info(f"Response status code: {response.status_code}")
            
            # Log benign activity
            log_attack_event("benign_web_access", {
                "site": site,
                "status_code": response.status_code,
                "iteration": i + 1
            })
            
            # Random delay
            delay = random.uniform(2, 8)
            logger.info(f"Waiting {delay:.1f} seconds...")
            time.sleep(delay)
            
        except requests.RequestException as e:
            logger.warning(f"Failed to access {site}: {e}")
            log_attack_event("benign_access_failed", {
                "site": site,
                "error": str(e)
            })
        except Exception as e:
            logger.error(f"Error executing benign activity: {e}")
    
    logger.info("Benign network activities completed")
    log_attack_event("benign_activity_complete", {"total_requests": 5})
