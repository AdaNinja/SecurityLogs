#!/usr/bin/env python3
"""
WAF Simulation Analysis Hook
Analyzes attack patterns and simulates WAF blocking behavior
"""

import os
import sys
import re
import json
import logging
from pathlib import Path
from datetime import datetime

def setup_logging():
    """Setup logging for the hook"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

def analyze_waf_simulation():
    """Analyze logs to simulate WAF behavior"""
    logger = setup_logging()
    
    logger.info("Starting WAF simulation analysis")
    
    # Get experiment directory from environment
    experiment_dir = os.environ.get('EXPERIMENT_DIR', 'logs')
    scenario_name = os.environ.get('scenario_name', 'unknown')
    
    # Attack patterns that would be blocked by a real WAF
    waf_patterns = {
        'sql_injection': [
            r"union\s+select",
            r"or\s+1\s*=\s*1",
            r"'\s*or\s*'",
            r"drop\s+table",
            r"select\s+\*\s+from",
            r"--\s*$",
            r";\s*select",
            r"exec\s*\(",
            r"xp_cmdshell"
        ],
        'xss': [
            r"<script[^>]*>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"alert\s*\(",
            r"<iframe",
            r"document\.cookie",
            r"eval\s*\(",
            r"expression\s*\("
        ],
        'path_traversal': [
            r"\.\./",
            r"\.\.\\",
            r"/etc/passwd",
            r"windows\\system32"
        ]
    }
    
    # Analyze nginx access logs
    nginx_log_path = Path(experiment_dir) / 'nginx' / 'detailed.log'
    if not nginx_log_path.exists():
        logger.warning(f"Nginx log not found: {nginx_log_path}")
        return False
    
    # Statistics
    total_requests = 0
    blocked_requests = 0
    attack_types_found = {}
    
    # Create WAF simulation report
    waf_report_path = Path(experiment_dir) / 'waf_simulation_report.json'
    blocked_entries = []
    
    try:
        with open(nginx_log_path, 'r') as f:
            for line in f:
                total_requests += 1
                
                # Check if line contains attack patterns
                for attack_type, patterns in waf_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            blocked_requests += 1
                            attack_types_found[attack_type] = attack_types_found.get(attack_type, 0) + 1
                            
                            # Extract request details
                            parts = line.split('"')
                            if len(parts) >= 2:
                                request = parts[1]
                                ip_match = re.match(r'^(\S+)', line)
                                ip = ip_match.group(1) if ip_match else 'unknown'
                                
                                blocked_entry = {
                                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                                    'source_ip': ip,
                                    'attack_type': attack_type,
                                    'pattern_matched': pattern,
                                    'request': request,
                                    'action': 'blocked',
                                    'waf_rule': f'RULE_{attack_type.upper()}_{patterns.index(pattern) + 1}'
                                }
                                blocked_entries.append(blocked_entry)
                            break
                    else:
                        continue
                    break
        
        # Calculate statistics
        block_rate = (blocked_requests / total_requests * 100) if total_requests > 0 else 0
        
        # Generate report
        report = {
            'scenario': scenario_name,
            'analysis_time': datetime.utcnow().isoformat() + 'Z',
            'summary': {
                'total_requests': total_requests,
                'blocked_requests': blocked_requests,
                'allowed_requests': total_requests - blocked_requests,
                'block_rate': f"{block_rate:.2f}%",
                'attack_types_detected': attack_types_found
            },
            'blocked_requests': blocked_entries[:100],  # Limit to first 100 for readability
            'waf_effectiveness': {
                'sql_injection_blocked': attack_types_found.get('sql_injection', 0),
                'xss_blocked': attack_types_found.get('xss', 0),
                'path_traversal_blocked': attack_types_found.get('path_traversal', 0)
            }
        }
        
        # Write report
        with open(waf_report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"WAF Simulation Analysis Complete:")
        logger.info(f"  Total Requests: {total_requests}")
        logger.info(f"  Blocked Requests: {blocked_requests} ({block_rate:.2f}%)")
        logger.info(f"  Attack Types: {attack_types_found}")
        logger.info(f"  Report saved to: {waf_report_path}")
        
        # Also create a simple CSV summary
        csv_path = Path(experiment_dir) / 'waf_simulation_summary.csv'
        with open(csv_path, 'w') as f:
            f.write("metric,value\n")
            f.write(f"total_requests,{total_requests}\n")
            f.write(f"blocked_requests,{blocked_requests}\n")
            f.write(f"allowed_requests,{total_requests - blocked_requests}\n")
            f.write(f"block_rate_percent,{block_rate:.2f}\n")
            for attack_type, count in attack_types_found.items():
                f.write(f"{attack_type}_blocked,{count}\n")
        
        return True
        
    except Exception as e:
        logger.error(f"WAF simulation analysis failed: {e}")
        return False

def main():
    """Main function"""
    success = analyze_waf_simulation()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
