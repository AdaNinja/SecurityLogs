#!/usr/bin/env python3
"""
Enhanced Log Processor for RAS Security Logs
Analyzes tool status, fallback mechanisms, and attack results
"""

import os
import json
import re
import glob
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import argparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EnhancedLogProcessor:
    """Enhanced log processor with tool status analysis"""
    
    def __init__(self, output_dir: str, mode: str = "attack-only"):
        self.output_dir = output_dir
        self.mode = mode
        self.logs_dir = os.path.join(output_dir, mode)
        self.tool_status = {}
        self.fallback_analysis = {}
        self.attack_results = {}
        
    def parse_attack_log(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse attack log with enhanced tool status detection"""
        try:
            # Look for tool status indicators
            if "TOOL_STATUS:" in log_line:
                tool_status_match = re.search(r'TOOL_STATUS:\s*(.+)', log_line)
                if tool_status_match:
                    return {
                        "log_type": "tool_status",
                        "status": tool_status_match.group(1).strip(),
                        "raw_line": log_line
                    }
            
            # Look for fallback status indicators
            if "FALLBACK_STATUS:" in log_line:
                fallback_match = re.search(r'FALLBACK_STATUS:\s*(.+)', log_line)
                if fallback_match:
                    return {
                        "log_type": "fallback_status",
                        "status": fallback_match.group(1).strip(),
                        "raw_line": log_line
                    }
            
            # Look for tool used indicators
            if "TOOL_USED:" in log_line:
                tool_used_match = re.search(r'TOOL_USED:\s*(.+)', log_line)
                if tool_used_match:
                    return {
                        "log_type": "tool_used",
                        "tool": tool_used_match.group(1).strip(),
                        "raw_line": log_line
                    }
            
            # Look for attack start/end markers
            if "===ATTACK_START===" in log_line:
                return {"log_type": "attack_start", "raw_line": log_line}
            elif "===ATTACK_END===" in log_line:
                return {"log_type": "attack_end", "raw_line": log_line}
            elif "PAYLOAD_ID:" in log_line:
                # Parse payload information
                payload_match = re.search(r'PAYLOAD_ID:\s*(\d+)', log_line)
                attack_type_match = re.search(r'ATTACK_TYPE:\s*(\w+)', log_line)
                tool_match = re.search(r'TOOL:\s*(\w+)', log_line)
                description_match = re.search(r'DESCRIPTION:\s*(.+)', log_line)
                timestamp_match = re.search(r'TIMESTAMP:\s*(.+)', log_line)
                
                if payload_match:
                    return {
                        "log_type": "attack_payload",
                        "payload_id": int(payload_match.group(1)),
                        "attack_type": attack_type_match.group(1) if attack_type_match else None,
                        "tool": tool_match.group(1) if tool_match else None,
                        "description": description_match.group(1) if description_match else None,
                        "timestamp": timestamp_match.group(1) if timestamp_match else None,
                        "raw_line": log_line
                    }
            
            # Look for success/failure indicators
            if "SUCCESS:" in log_line or "FAILED:" in log_line:
                success_match = re.search(r'\[SUCCESS\]\s*(.+)', log_line)
                failed_match = re.search(r'\[FAILED\]\s*(.+)', log_line)
                
                if success_match:
                    return {
                        "log_type": "attack_success",
                        "message": success_match.group(1).strip(),
                        "raw_line": log_line
                    }
                elif failed_match:
                    return {
                        "log_type": "attack_failed",
                        "message": failed_match.group(1).strip(),
                        "raw_line": log_line
                    }
            
            # Look for error indicators
            if "ERROR:" in log_line:
                error_match = re.search(r'\[ERROR\]\s*(.+)', log_line)
                if error_match:
                    return {
                        "log_type": "tool_error",
                        "error": error_match.group(1).strip(),
                        "raw_line": log_line
                    }
            
        except Exception as e:
            logger.warning(f"Failed to parse attack log line: {e}")
        return None
    
    def process_attack_logs(self) -> Dict[str, Any]:
        """Process attack logs with enhanced analysis"""
        attack_logs = []
        attacker_dir = os.path.join(self.logs_dir, "attacker")
        
        if not os.path.exists(attacker_dir):
            logger.warning(f"Attacker logs directory not found: {attacker_dir}")
            return {}
        
        attack_log = os.path.join(attacker_dir, "attack.log")
        if os.path.exists(attack_log):
            logger.info(f"Processing attack log: {attack_log}")
            
            current_payload = None
            current_tool = None
            current_status = None
            
            with open(attack_log, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line:
                        parsed = self.parse_attack_log(line)
                        if parsed:
                            parsed["line_number"] = line_num
                            parsed["source_file"] = "attack.log"
                            parsed["log_source"] = "attacker"
                            attack_logs.append(parsed)
                            
                            # Track current payload and tool
                            if parsed.get("log_type") == "attack_payload":
                                current_payload = parsed.get("payload_id")
                                current_tool = parsed.get("tool")
                            elif parsed.get("log_type") == "tool_status":
                                current_status = parsed.get("status")
                                if current_payload and current_tool:
                                    self.tool_status[f"{current_tool}_{current_payload}"] = current_status
                            elif parsed.get("log_type") == "fallback_status":
                                if current_payload and current_tool:
                                    self.fallback_analysis[f"{current_tool}_{current_payload}"] = parsed.get("status")
        
        logger.info(f"Processed {len(attack_logs)} attack log entries")
        return attack_logs
    
    def analyze_tool_availability(self) -> Dict[str, Any]:
        """Analyze tool availability and fallback usage"""
        analysis = {
            "tools_available": {},
            "tools_missing": {},
            "fallback_usage": {},
            "success_rates": {}
        }
        
        # Analyze tool status
        for key, status in self.tool_status.items():
            tool, payload = key.split('_', 1)
            
            if "SUCCESS" in status:
                if tool not in analysis["tools_available"]:
                    analysis["tools_available"][tool] = []
                analysis["tools_available"][tool].append(payload)
            elif "FAILED" in status:
                if tool not in analysis["tools_missing"]:
                    analysis["tools_missing"][tool] = []
                analysis["tools_missing"][tool].append(payload)
        
        # Analyze fallback usage
        for key, fallback_status in self.fallback_analysis.items():
            tool, payload = key.split('_', 1)
            
            if "NOT_AVAILABLE" in fallback_status:
                if tool not in analysis["fallback_usage"]:
                    analysis["fallback_usage"][tool] = {"not_available": [], "used": []}
                analysis["fallback_usage"][tool]["not_available"].append(payload)
            elif "ACTIVATED" in fallback_status:
                if tool not in analysis["fallback_usage"]:
                    analysis["fallback_usage"][tool] = {"not_available": [], "used": []}
                analysis["fallback_usage"][tool]["used"].append(payload)
        
        return analysis
    
    def generate_enhanced_summary(self, attack_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate enhanced summary with tool analysis"""
        summary = {
            "mode": self.mode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "log_counts": {
                "total_attack_entries": len(attack_logs),
                "tool_status_entries": len([l for l in attack_logs if l.get("log_type") == "tool_status"]),
                "fallback_entries": len([l for l in attack_logs if l.get("log_type") == "fallback_status"]),
                "attack_payloads": len([l for l in attack_logs if l.get("log_type") == "attack_payload"]),
                "successful_attacks": len([l for l in attack_logs if l.get("log_type") == "attack_success"]),
                "failed_attacks": len([l for l in attack_logs if l.get("log_type") == "attack_failed"]),
                "tool_errors": len([l for l in attack_logs if l.get("log_type") == "tool_error"])
            },
            "tool_analysis": self.analyze_tool_availability(),
            "attack_types": {},
            "tools_used": {}
        }
        
        # Count attack types and tools
        for log in attack_logs:
            if log.get("log_type") == "attack_payload":
                attack_type = log.get("attack_type")
                tool = log.get("tool")
                
                if attack_type:
                    summary["attack_types"][attack_type] = summary["attack_types"].get(attack_type, 0) + 1
                
                if tool:
                    summary["tools_used"][tool] = summary["tools_used"].get(tool, 0) + 1
        
        return summary
    
    def save_enhanced_analysis(self, analysis: Dict[str, Any], filename: str):
        """Save enhanced analysis to JSON file"""
        output_file = os.path.join(self.logs_dir, filename)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False, default=str)
        logger.info(f"Saved enhanced analysis to {output_file}")
    
    def process_all_logs(self):
        """Process all logs with enhanced analysis"""
        logger.info(f"Starting enhanced log processing for mode: {self.mode}")
        
        # Process attack logs
        attack_logs = self.process_attack_logs()
        
        # Generate enhanced summary
        summary = self.generate_enhanced_summary(attack_logs)
        
        # Save enhanced analysis
        self.save_enhanced_analysis(summary, "enhanced_analysis.json")
        
        # Save detailed attack logs
        if attack_logs:
            self.save_enhanced_analysis(attack_logs, "detailed_attack_logs.json")
        
        logger.info("Enhanced log processing completed")
        return summary

def main():
    parser = argparse.ArgumentParser(description="Enhanced multi-source security log processor")
    parser.add_argument("--output-dir", required=True, help="Output directory containing logs")
    parser.add_argument("--mode", default="attack-only", help="Log mode (attack-only, benign-only, mixed)")
    
    args = parser.parse_args()
    
    processor = EnhancedLogProcessor(args.output_dir, args.mode)
    summary = processor.process_all_logs()
    
    print(f"\nEnhanced Analysis Summary:")
    print(f"Mode: {summary['mode']}")
    print(f"Timestamp: {summary['timestamp']}")
    print(f"\nLog Counts:")
    for key, count in summary['log_counts'].items():
        print(f"  {key}: {count}")
    
    print(f"\nTool Analysis:")
    tool_analysis = summary['tool_analysis']
    print(f"  Tools Available:")
    for tool, payloads in tool_analysis['tools_available'].items():
        print(f"    {tool}: {len(payloads)} payloads")
    
    print(f"  Tools Missing:")
    for tool, payloads in tool_analysis['tools_missing'].items():
        print(f"    {tool}: {len(payloads)} payloads")
    
    print(f"  Fallback Usage:")
    for tool, fallback_info in tool_analysis['fallback_usage'].items():
        print(f"    {tool}: {len(fallback_info['not_available'])} not available, {len(fallback_info['used'])} used")
    
    print(f"\nAttack Types:")
    for attack_type, count in summary['attack_types'].items():
        print(f"  {attack_type}: {count}")
    
    print(f"\nTools Used:")
    for tool, count in summary['tools_used'].items():
        print(f"  {tool}: {count}")

if __name__ == "__main__":
    main() 