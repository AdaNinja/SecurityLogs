#!/usr/bin/env python3
"""
Logging utility module - Provides log labeling and delay functionality
    Inject attack phase labels into system logs
    Provide controllable delayed execution
    Record detailed attack event information
"""

import subprocess
import time
import logging
from typing import Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def inject_label(label: str):
    """
    Inject attack phase label into system logs
    
    Args:
        label: Label string, format like "phase=Reconnaissance"
    """
    try:
        result = subprocess.run(
            ["logger", "-t", "APT", label],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            logger.info(f"Successfully injected label: {label}")
        else:
            logger.error(f"Failed to inject label: {result.stderr}")
    except subprocess.TimeoutExpired:
        logger.error("Label injection timeout")
    except Exception as e:
        logger.error(f"Error during label injection: {e}")

def sleep(sec: int):
    """
    Delay execution
    
    Args:
        sec: Delay seconds
    """
    logger.info(f"Delaying {sec} seconds...")
    time.sleep(sec)
    logger.info("Delay completed")

def log_attack_event(event_type: str, details: Optional[dict] = None):
    """
    Log attack event
    
    Args:
        event_type: Event type
        details: Event details
    """
    event_data = {
        'event_type': event_type,
        'timestamp': time.time(),
        'details': details or {}
    }
    
    label = f"attack_event={event_type}"
    if details:
        for key, value in details.items():
            label += f" {key}={value}"
    
    inject_label(label)
    logger.info(f"Logged attack event: {event_type} - {details}")
