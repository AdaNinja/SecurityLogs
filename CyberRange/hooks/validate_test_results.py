#!/usr/bin/env python3
"""
Validate Test Results Hook
Validates that test scenario executed correctly and all attack types were covered
"""

import os
import sys
import json
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def validate_nginx_logs(log_dir):
    """Validate nginx detailed.log contains expected attack types"""
    detailed_log = Path(log_dir) / "nginx" / "detailed.log"
    
    if not detailed_log.exists():
        logger.error(f"Nginx detailed.log not found: {detailed_log}")
        return False
    
    logger.info(f"Validating nginx logs: {detailed_log}")
    
    # Expected attack types based on test_all_features.yaml
    expected_attack_types = ['sql', 'xss', 'cmd', 'dir', 'auth', 'file', 'method']
    found_attack_types = set()
    
    attack_count = 0
    benign_count = 0
    
    try:
        with open(detailed_log, 'r') as f:
            for line in f:
                if 'attacker' in line:
                    attack_count += 1
                    # Extract attack type from the log line
                    parts = line.split('"')
                    if len(parts) >= 14:
                        attack_type = parts[13].strip()
                        if attack_type != '-':
                            found_attack_types.add(attack_type)
                elif 'benign' in line or 'Mozilla' in line:
                    benign_count += 1
    
    except Exception as e:
        logger.error(f"Error reading nginx log: {e}")
        return False
    
    logger.info(f"Found {attack_count} attack requests")
    logger.info(f"Found {benign_count} benign requests")
    logger.info(f"Attack types found: {sorted(found_attack_types)}")
    
    # Check if we have all expected attack types
    missing_types = set(expected_attack_types) - found_attack_types
    if missing_types:
        logger.warning(f"Missing attack types: {missing_types}")
    else:
        logger.info("✅ All expected attack types found")
    
    return attack_count > 0 and benign_count > 0

def validate_attacker_logs(log_dir):
    """Validate attacker logs exist and contain structured data"""
    attacker_dir = Path(log_dir) / "attacker"
    
    if not attacker_dir.exists():
        logger.error(f"Attacker log directory not found: {attacker_dir}")
        return False
    
    log_files = list(attacker_dir.glob("attack_*.log"))
    structured_files = list(attacker_dir.glob("structured_attack_*.log"))
    
    logger.info(f"Found {len(log_files)} attack log files")
    logger.info(f"Found {len(structured_files)} structured log files")
    
    if len(log_files) == 0:
        logger.error("No attack log files found")
        return False
    
    # Sample one log file to check format
    if log_files:
        sample_log = log_files[0]
        try:
            with open(sample_log, 'r') as f:
                content = f.read()
                if 'CyberRange Unified Attack Script' in content:
                    logger.info("✅ Attack scripts executed correctly")
                else:
                    logger.warning("⚠️ Attack script format not recognized")
        except Exception as e:
            logger.error(f"Error reading attack log: {e}")
            return False
    
    return True

def validate_benign_logs(log_dir):
    """Validate benign user logs exist and contain activity"""
    benign_log = Path(log_dir) / "benign_user" / "user.log"
    
    if not benign_log.exists():
        logger.error(f"Benign user log not found: {benign_log}")
        return False
    
    logger.info(f"Validating benign logs: {benign_log}")
    
    try:
        with open(benign_log, 'r') as f:
            content = f.read()
            if 'SUCCESS GET' in content or 'SUCCESS POST' in content:
                logger.info("✅ Benign user activity found")
                return True
            else:
                logger.warning("⚠️ No successful benign activity found")
                return False
    except Exception as e:
        logger.error(f"Error reading benign log: {e}")
        return False

def generate_summary_report(log_dir):
    """Generate a summary report of the test execution"""
    summary = {
        "scenario": "test-all-features",
        "timestamp": Path(log_dir).name.split('_')[-2:],
        "validation_results": {},
        "statistics": {}
    }
    
    # Nginx log stats
    detailed_log = Path(log_dir) / "nginx" / "detailed.log"
    if detailed_log.exists():
        try:
            with open(detailed_log, 'r') as f:
                lines = f.readlines()
                attack_lines = [l for l in lines if 'attacker' in l]
                benign_lines = [l for l in lines if 'benign' in l or 'Mozilla' in l]
                
                summary["statistics"]["total_requests"] = len(lines)
                summary["statistics"]["attack_requests"] = len(attack_lines)
                summary["statistics"]["benign_requests"] = len(benign_lines)
                summary["statistics"]["attack_percentage"] = (len(attack_lines) / len(lines)) * 100 if lines else 0
        except Exception as e:
            logger.error(f"Error analyzing nginx log: {e}")
    
    # Attacker log stats
    attacker_dir = Path(log_dir) / "attacker"
    if attacker_dir.exists():
        log_files = list(attacker_dir.glob("attack_*.log"))
        summary["statistics"]["attack_log_files"] = len(log_files)
    
    # Network capture stats
    pcap_file = Path(log_dir) / "network_traffic.pcap"
    if pcap_file.exists():
        summary["statistics"]["pcap_size_mb"] = round(pcap_file.stat().st_size / (1024*1024), 2)
    
    # Write summary report
    report_file = Path(log_dir) / "validation_report.json"
    try:
        with open(report_file, 'w') as f:
            json.dump(summary, f, indent=2)
        logger.info(f"📊 Summary report written to: {report_file}")
    except Exception as e:
        logger.error(f"Error writing summary report: {e}")
    
    return summary

def main():
    """Main validation function"""
    # Get log directory from environment or command line
    if len(sys.argv) > 1:
        log_dir = sys.argv[1]
    else:
        # Try to find the most recent test-all-features log directory
        logs_dir = Path("logs")
        if logs_dir.exists():
            test_dirs = [d for d in logs_dir.iterdir() if d.is_dir() and "test-all-features" in d.name]
            if test_dirs:
                log_dir = str(sorted(test_dirs)[-1])  # Most recent
            else:
                logger.error("No test-all-features log directory found")
                return False
        else:
            logger.error("Logs directory not found")
            return False
    
    logger.info(f"🔍 Validating test results in: {log_dir}")
    
    # Run validations
    validations = {
        "nginx_logs": validate_nginx_logs(log_dir),
        "attacker_logs": validate_attacker_logs(log_dir),
        "benign_logs": validate_benign_logs(log_dir)
    }
    
    # Generate summary report
    summary = generate_summary_report(log_dir)
    summary["validation_results"] = validations
    
    # Print results
    logger.info("📊 Validation Results:")
    for check, result in validations.items():
        status = "✅ PASS" if result else "❌ FAIL"
        logger.info(f"   {check}: {status}")
    
    if "statistics" in summary:
        stats = summary["statistics"]
        logger.info("📈 Statistics:")
        for key, value in stats.items():
            logger.info(f"   {key}: {value}")
    
    # Overall result
    all_passed = all(validations.values())
    if all_passed:
        logger.info("🎉 All validations passed!")
    else:
        logger.warning("⚠️ Some validations failed")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
