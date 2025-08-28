#!/usr/bin/env python3
"""
Universal Scenario Results Analysis Hook
Analyzes results from any CyberRange scenario and generates comprehensive reports
Works with all scenario types: test, production, ML dataset, advanced attacks
"""

import os
import sys
import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
import pandas as pd

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def detect_scenario_type(logs_dir):
    """Detect what type of scenario was executed based on log contents"""
    scenario_types = []
    
    # Check for different attack patterns
    nginx_log = Path(logs_dir) / "nginx" / "detailed.log"
    if nginx_log.exists():
        try:
            with open(nginx_log, 'r') as f:
                content = f.read()
                
                if 'phase1' in content or 'phase2' in content:
                    scenario_types.append("multi_phase")
                if '"sql"' in content or '"xss"' in content:
                    scenario_types.append("basic_attacks")
                if 'lateral_movement' in content:
                    scenario_types.append("lateral_movement")
                if len([l for l in content.split('\n') if 'attacker' in l]) > 100:
                    scenario_types.append("high_volume")
                    
        except Exception as e:
            logger.warning(f"Error analyzing nginx log: {e}")
    
    return scenario_types if scenario_types else ["unknown"]

def analyze_attack_distribution(logs_dir):
    """Analyze distribution of attack types"""
    nginx_log = Path(logs_dir) / "nginx" / "detailed.log"
    
    if not nginx_log.exists():
        return {}
    
    attack_distribution = {}
    total_attacks = 0
    total_benign = 0
    
    try:
        with open(nginx_log, 'r') as f:
            for line in f:
                if 'attacker' in line:
                    total_attacks += 1
                    # Extract attack type from log line
                    parts = line.split('"')
                    if len(parts) >= 14:
                        attack_type = parts[13].strip()
                        if attack_type != '-':
                            attack_distribution[attack_type] = attack_distribution.get(attack_type, 0) + 1
                elif 'benign' in line or 'Mozilla' in line:
                    total_benign += 1
    
    except Exception as e:
        logger.error(f"Error analyzing attack distribution: {e}")
        return {}
    
    # Calculate percentages
    total_requests = total_attacks + total_benign
    distribution_stats = {
        "total_requests": total_requests,
        "attack_requests": total_attacks,
        "benign_requests": total_benign,
        "attack_percentage": (total_attacks / total_requests) * 100 if total_requests > 0 else 0,
        "attack_types": attack_distribution
    }
    
    return distribution_stats


def analyze_attack_success_rate(logs_dir):
    """Analyze attack success and failure rates from attacker logs"""
    attacker_dir = Path(logs_dir) / "attacker"
    
    attack_success_count = 0
    attack_failure_count = 0
    attack_error_count = 0
    total_attack_attempts = 0
    attack_types_success = {}
    attack_types_failure = {}
    
    try:
        if attacker_dir.exists():
            # Process all structured attack log files
            for log_file in attacker_dir.glob("structured_attack_*.log"):
                try:
                    with open(log_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and line.startswith('{'):
                                try:
                                    log_entry = json.loads(line)
                                    level = log_entry.get('level', '')
                                    attack_type = log_entry.get('attack_type', 'unknown')
                                    message = log_entry.get('message', '')
                                    
                                    # Count attack attempts (both successful and failed)
                                    if (level == 'SUCCESS' and 'Attack successful' in message) or \
                                       (level == 'WARNING' and 'Unexpected response' in message) or \
                                       (level == 'ERROR' and ('Attack' in message or 'attack' in message.lower())):
                                        total_attack_attempts += 1
                                        
                                        if level == 'SUCCESS' and 'Attack successful' in message:
                                            attack_success_count += 1
                                            attack_types_success[attack_type] = attack_types_success.get(attack_type, 0) + 1
                                        elif level == 'WARNING' and 'Unexpected response' in message:
                                            attack_failure_count += 1
                                            attack_types_failure[attack_type] = attack_types_failure.get(attack_type, 0) + 1
                                        elif level == 'ERROR':
                                            attack_error_count += 1
                                            attack_types_failure[attack_type] = attack_types_failure.get(attack_type, 0) + 1
                                
                                except json.JSONDecodeError:
                                    continue
                                    
                except Exception as e:
                    logger.warning(f"Error processing attack log {log_file}: {e}")
                    continue
    
    except Exception as e:
        logger.error(f"Error analyzing attack success rate: {e}")
    
    success_rate = (attack_success_count / total_attack_attempts * 100) if total_attack_attempts > 0 else 0
    failure_rate = ((attack_failure_count + attack_error_count) / total_attack_attempts * 100) if total_attack_attempts > 0 else 0
    
    success_stats = {
        "total_attack_attempts": total_attack_attempts,
        "successful_attacks": attack_success_count,
        "failed_attacks": attack_failure_count + attack_error_count,
        "warning_attacks": attack_failure_count,
        "error_attacks": attack_error_count,
        "success_rate_percentage": round(success_rate, 2),
        "failure_rate_percentage": round(failure_rate, 2),
        "success_by_type": attack_types_success,
        "failure_by_type": attack_types_failure
    }
    
    return success_stats


def analyze_timing_patterns(logs_dir):
    """Analyze timing patterns of attacks and benign traffic"""
    nginx_log = Path(logs_dir) / "nginx" / "detailed.log"
    
    if not nginx_log.exists():
        return {}
    
    timestamps = []
    attack_times = []
    benign_times = []
    
    try:
        with open(nginx_log, 'r') as f:
            for line in f:
                # Extract timestamp
                if '[' in line and ']' in line:
                    timestamp_part = line.split('[')[1].split(']')[0]
                    try:
                        # Parse nginx timestamp format
                        dt = datetime.strptime(timestamp_part, '%d/%b/%Y:%H:%M:%S %z')
                        timestamps.append(dt)
                        
                        if 'attacker' in line:
                            attack_times.append(dt)
                        elif 'benign' in line or 'Mozilla' in line:
                            benign_times.append(dt)
                    except ValueError:
                        continue
    
    except Exception as e:
        logger.error(f"Error analyzing timing patterns: {e}")
        return {}
    
    if not timestamps:
        return {}
    
    # Calculate timing statistics
    total_duration = (max(timestamps) - min(timestamps)).total_seconds()
    timing_stats = {
        "start_time": min(timestamps).isoformat(),
        "end_time": max(timestamps).isoformat(),
        "total_duration_seconds": total_duration,
        "attack_frequency": len(attack_times) / total_duration * 60 if total_duration > 0 else 0,  # per minute
        "benign_frequency": len(benign_times) / total_duration * 60 if total_duration > 0 else 0,   # per minute
        "total_frequency": len(timestamps) / total_duration * 60 if total_duration > 0 else 0        # per minute
    }
    
    return timing_stats

def analyze_response_codes(logs_dir):
    """Analyze HTTP response codes distribution"""
    nginx_log = Path(logs_dir) / "nginx" / "detailed.log"
    
    if not nginx_log.exists():
        return {}
    
    response_codes = {}
    attack_responses = {}
    benign_responses = {}
    
    try:
        with open(nginx_log, 'r') as f:
            for line in f:
                # Extract response code (format: "METHOD /path HTTP/1.1" CODE size)
                parts = line.split('"')
                if len(parts) >= 3:
                    after_request = parts[2].strip()
                    code_parts = after_request.split()
                    if code_parts:
                        try:
                            code = int(code_parts[0])
                            response_codes[code] = response_codes.get(code, 0) + 1
                            
                            if 'attacker' in line:
                                attack_responses[code] = attack_responses.get(code, 0) + 1
                            elif 'benign' in line or 'Mozilla' in line:
                                benign_responses[code] = benign_responses.get(code, 0) + 1
                        except (ValueError, IndexError):
                            continue
    
    except Exception as e:
        logger.error(f"Error analyzing response codes: {e}")
        return {}
    
    return {
        "overall": response_codes,
        "attack": attack_responses,
        "benign": benign_responses
    }

def copy_logs_to_output(logs_dir, output_dir):
    """Copy important log files to output directory for preservation"""
    try:
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Copy key files
        files_to_copy = [
            ("nginx/detailed.log", "nginx_detailed.log"),
            ("nginx/access.log", "nginx_access.log"),
            ("nginx/error.log", "nginx_error.log"),
            ("benign_user/user.log", "benign_user.log"),
            ("network_traffic.pcap", "network_traffic.pcap")
        ]
        
        for src_path, dst_name in files_to_copy:
            src = Path(logs_dir) / src_path
            if src.exists():
                dst = Path(output_dir) / dst_name
                shutil.copy2(src, dst)
                logger.info(f"Copied {src_path} to {dst_name}")
        
        # Copy attacker logs (multiple files)
        attacker_dir = Path(logs_dir) / "attacker"
        if attacker_dir.exists():
            output_attacker_dir = Path(output_dir) / "attacker_logs"
            os.makedirs(output_attacker_dir, exist_ok=True)
            
            # Copy structured logs (more important)
            for log_file in attacker_dir.glob("structured_attack_*.log"):
                shutil.copy2(log_file, output_attacker_dir / log_file.name)
            
            logger.info(f"Copied attacker logs to attacker_logs/")
    
    except Exception as e:
        logger.error(f"Error copying logs to output: {e}")

def generate_comprehensive_report(logs_dir):
    """Generate comprehensive analysis report"""
    logger.info("Starting comprehensive scenario analysis")
    
    # Detect scenario type
    scenario_types = detect_scenario_type(logs_dir)
    logger.info(f"Detected scenario types: {scenario_types}")
    
    # Run all analyses
    analysis_results = {
        "analysis_metadata": {
            "timestamp": datetime.now().isoformat(),
            "logs_directory": str(logs_dir),
            "scenario_types": scenario_types,
            "analyzer_version": "1.0.0"
        },
        "attack_distribution": analyze_attack_distribution(logs_dir),
        "attack_success_rate": analyze_attack_success_rate(logs_dir),
        "timing_patterns": analyze_timing_patterns(logs_dir),
        "response_codes": analyze_response_codes(logs_dir)
    }
    
    # Determine output directory
    logs_path = Path(logs_dir)
    scenario_name = logs_path.name.split('_')[0]  # Extract scenario name from directory
    output_dir = Path("output") / logs_path.name
    
    # Copy logs to output
    copy_logs_to_output(logs_dir, output_dir)
    
    # Save analysis report
    report_file = output_dir / "scenario_analysis_report.json"
    try:
        with open(report_file, 'w') as f:
            json.dump(analysis_results, f, indent=2, default=str)
        logger.info(f"📊 Comprehensive report saved to: {report_file}")
    except Exception as e:
        logger.error(f"Error saving report: {e}")
    
    # Print summary
    stats = analysis_results.get("attack_distribution", {})
    timing = analysis_results.get("timing_patterns", {})
    
    logger.info("📈 Analysis Summary:")
    logger.info(f"   Total requests: {stats.get('total_requests', 0)}")
    logger.info(f"   Attack requests: {stats.get('attack_requests', 0)}")
    logger.info(f"   Benign requests: {stats.get('benign_requests', 0)}")
    logger.info(f"   Attack percentage: {stats.get('attack_percentage', 0):.1f}%")
    
    if timing:
        logger.info(f"   Duration: {timing.get('total_duration_seconds', 0):.1f} seconds")
        logger.info(f"   Attack frequency: {timing.get('attack_frequency', 0):.1f} per minute")
    
    attack_types = stats.get('attack_types', {})
    if attack_types:
        logger.info(f"   Attack types: {list(attack_types.keys())}")
    
    return analysis_results

def main():
    """Main analysis function"""
    # Get logs directory from command line or find most recent
    if len(sys.argv) > 1:
        logs_dir = sys.argv[1]
    else:
        # Find most recent log directory
        logs_base = Path("logs")
        if logs_base.exists():
            log_dirs = [d for d in logs_base.iterdir() if d.is_dir()]
            if log_dirs:
                logs_dir = str(max(log_dirs, key=lambda x: x.stat().st_mtime))
            else:
                logger.error("No log directories found")
                return False
        else:
            logger.error("Logs directory not found")
            return False
    
    logger.info(f"🔍 Analyzing scenario results in: {logs_dir}")
    
    try:
        results = generate_comprehensive_report(logs_dir)
        logger.info("✅ Scenario analysis completed successfully")
        return True
    except Exception as e:
        logger.error(f"❌ Analysis failed: {e}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
