#!/usr/bin/env python3
"""
Scenario scheduler entry - Main controller for executing attack scenarios
"""

import argparse
import yaml
import importlib
import logging
from logger_utils import inject_label, sleep, log_attack_event

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Execute attack scenario')
    parser.add_argument("--config", required=True, help="Scenario configuration file path")
    parser.add_argument("--dry-run", action="store_true", help="Only display configuration, do not execute")
    args = parser.parse_args()
    
    try:
        # Load configuration file
        logger.info(f"Loading configuration file: {args.config}")
        with open(args.config, 'r', encoding='utf-8') as f:
            cfg = yaml.safe_load(f)
        
        if args.dry_run:
            logger.info("DRY RUN mode - Configuration content:")
            logger.info(yaml.dump(cfg, default_flow_style=False))
            return
        
        logger.info(f"Starting scenario execution: {cfg['name']}")
        
        # 1. Reconnaissance phase
        logger.info("=== Phase 1: Reconnaissance ===")
        inject_label("phase=Reconnaissance")
        log_attack_event("reconnaissance_start", {"scenario": cfg['name']})
        
        try:
            benign_module = importlib.import_module(f"scenarios.{cfg['name']}.benign")
            benign_module.run(cfg["parameters"])
            log_attack_event("reconnaissance_complete")
        except Exception as e:
            logger.error(f"Reconnaissance phase failed: {e}")
            log_attack_event("reconnaissance_failed", {"error": str(e)})
            return
        
        # 2. Delay
        delay_seconds = cfg["parameters"].get("attack_delay_s", 30)
        logger.info(f"=== Delay {delay_seconds} seconds ===")
        sleep(delay_seconds)
        
        # 3. Delivery phase
        logger.info("=== Phase 2: Delivery ===")
        inject_label("phase=Delivery")
        log_attack_event("delivery_start")
        
        try:
            attack_module = importlib.import_module(f"scenarios.{cfg['name']}.attack")
            attack_module.run(cfg["parameters"])
            log_attack_event("delivery_complete")
        except Exception as e:
            logger.error(f"Delivery phase failed: {e}")
            log_attack_event("delivery_failed", {"error": str(e)})
            return
        
        # 4. Exploitation phase
        logger.info("=== Phase 3: Exploitation ===")
        inject_label("phase=Exploitation")
        log_attack_event("exploitation_start")
        
        # Additional exploitation logic can be added here
        sleep(5)  # Simulate exploitation process
        log_attack_event("exploitation_complete")
        
        logger.info("=== Scenario execution completed ===")
        inject_label("phase=Complete")
        log_attack_event("scenario_complete", {"scenario": cfg['name']})
        
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {args.config}")
    except yaml.YAMLError as e:
        logger.error(f"Configuration file format error: {e}")
    except Exception as e:
        logger.error(f"Error executing scenario: {e}")
        log_attack_event("scenario_failed", {"error": str(e)})

if __name__ == "__main__":
    main()
