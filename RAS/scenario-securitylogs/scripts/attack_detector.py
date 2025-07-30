#!/usr/bin/env python3
"""
Enhanced Attack Detection Engine
Supports unified YAML rules, JSON parsing, and structured log analysis
"""

import yaml
import json
import re
import sys
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
import argparse
from datetime import datetime
import jsonpath_ng as jsonpath

class AttackDetector:
    def __init__(self, rules_file: str):
        self.rules_file = rules_file
        self.rules = self._load_rules()
    
    def _load_rules(self) -> Dict[str, Any]:
        """Load detection rules from YAML file"""
        try:
            with open(self.rules_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"Error: Rules file {self.rules_file} not found")
            sys.exit(1)
        except yaml.YAMLError as e:
            print(f"Error parsing YAML rules file: {e}")
            sys.exit(1)
    
    def _evaluate_indicator(self, indicator: Dict[str, Any], data: Dict[str, Any]) -> bool:
        """Evaluate a single success/failure indicator"""
        for key, value in indicator.items():
            if key == 'jsonpath':
                # JSONPath evaluation
                try:
                    jsonpath_expr = jsonpath.parse(value)
                    matches = [match.value for match in jsonpath_expr.find(data.get('json_data', {}))]
                    if matches and any(matches):
                        return True
                except Exception as e:
                    print(f"Warning: JSONPath evaluation failed: {e}")
                    continue
            
            elif key == 'text':
                # Text pattern matching
                if re.search(value, data.get('text_data', ''), re.IGNORECASE):
                    return True
            
            elif key == 'status':
                # HTTP status code matching
                if isinstance(value, list):
                    if data.get('http_status') in value:
                        return True
                else:
                    if data.get('http_status') == value:
                        return True
            
            elif key == 'body_regex':
                # Response body regex matching
                if re.search(value, data.get('response_body', ''), re.IGNORECASE):
                    return True
            
            elif key == 'header_regex':
                # Response header regex matching
                if re.search(value, data.get('response_headers', ''), re.IGNORECASE):
                    return True
        
        return False
    
    def detect_attack(self, attack_type: str, attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect attack success/failure using unified indicators"""
        result = {
            'success': False,
            'confidence': 0.0,
            'evidence': [],
            'attack_type': attack_type
        }
        
        if attack_type not in self.rules:
            return result
        
        rule = self.rules[attack_type]
        
        # First check failure indicators (higher priority)
        if 'failure_indicators' in rule:
            for indicator in rule['failure_indicators']:
                if self._evaluate_indicator(indicator, attack_data):
                    result['success'] = False
                    result['confidence'] = 0.9
                    result['evidence'].append(f"Failure indicator matched: {indicator}")
                    return result
        
        # Then check success indicators
        if 'success_indicators' in rule:
            for indicator in rule['success_indicators']:
                if self._evaluate_indicator(indicator, attack_data):
                    result['success'] = True
                    result['confidence'] = 0.8
                    result['evidence'].append(f"Success indicator matched: {indicator}")
                    break
        
        return result
    
    def _parse_structured_log(self, attack_log: str) -> List[Dict[str, Any]]:
        """Parse structured attack log with clear markers"""
        attacks = []
        current_attack = {}
        in_attack_block = False
        
        for line in attack_log.split('\n'):
            line = line.strip()
            
            if line == "===ATTACK_START===":
                if in_attack_block:
                    # If we're already in an attack block, this is a duplicate marker
                    continue
                in_attack_block = True
                current_attack = {}
                continue
            
            elif line == "===ATTACK_END===":
                in_attack_block = False
                if current_attack:
                    attacks.append(current_attack)
                current_attack = {}
                continue
            
            elif in_attack_block and ':' in line:
                key, value = line.split(':', 1)
                current_attack[key.strip()] = value.strip()
        
        return attacks
    
    def _extract_http_responses(self, nginx_log: str) -> Dict[str, Dict[str, Any]]:
        """Extract HTTP responses from Nginx log with more detail"""
        responses = {}
        
        for line in nginx_log.split('\n'):
            if 'attacker' in line and 'HTTP' in line:
                # Extract timestamp, IP, method, path, status, size
                match = re.search(r'(\S+) - - \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) (\d+)', line)
                if match:
                    ip, timestamp, method, path, status, size = match.groups()
                    
                    # Create response key based on method and path
                    response_key = f"{method}_{path}"
                    
                    responses[response_key] = {
                        'timestamp': timestamp,
                        'ip': ip,
                        'method': method,
                        'path': path,
                        'status': int(status),
                        'size': int(size),
                        'raw_line': line
                    }
        
        return responses
    
    def _load_json_outputs(self, output_dir: str) -> Dict[str, Any]:
        """Load JSON outputs from sqlmap attacks"""
        json_data = {}
        
        if os.path.exists(output_dir):
            for file in os.listdir(output_dir):
                if file.endswith('_output.json'):
                    try:
                        with open(os.path.join(output_dir, file), 'r') as f:
                            json_data[file] = json.load(f)
                    except (json.JSONDecodeError, FileNotFoundError):
                        continue
        
        return json_data
    
    def analyze_attack_results(self, attack_log_file: str, 
                              nginx_log_file: str,
                              json_output_dir: str = "/tmp/sqlmap_attack") -> Dict[str, Any]:
        """Analyze attack results using enhanced detection"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'attack_summary': {},
            'overall_stats': {
                'total_attacks': 0,
                'successful_attacks': 0,
                'failed_attacks': 0,
                'success_rate': 0.0
            }
        }
        
        # Load log files
        try:
            with open(attack_log_file, 'r') as f:
                attack_log = f.read()
        except FileNotFoundError:
            print(f"Warning: Attack log file {attack_log_file} not found")
            attack_log = ""
        
        try:
            with open(nginx_log_file, 'r') as f:
                nginx_log = f.read()
        except FileNotFoundError:
            print(f"Warning: Nginx log file {nginx_log_file} not found")
            nginx_log = ""
        
        # Parse structured attack log
        attacks = self._parse_structured_log(attack_log)
        
        # Extract HTTP responses
        http_responses = self._extract_http_responses(nginx_log)
        
        # Load JSON outputs
        json_outputs = self._load_json_outputs(json_output_dir)
        
        # Analyze each attack
        for attack in attacks:
            attack_type = attack.get('ATTACK_TYPE', 'unknown')
            payload_id = attack.get('PAYLOAD_ID', 'unknown')
            
            # Prepare attack data for detection
            attack_data = {
                'text_data': attack_log,  # Full log for text pattern matching
                'http_status': None,
                'response_body': '',
                'response_headers': '',
                'json_data': {}
            }
            
            # Extract HTTP status from attack log if available
            if 'HTTP_CODE' in attack:
                try:
                    attack_data['http_status'] = int(attack['HTTP_CODE'])
                except (ValueError, KeyError):
                    pass
            
            # Match HTTP response
            method = attack.get('METHOD', 'GET')
            path = attack.get('PATH', '')
            response_key = f"{method}_{path}"
            
            if response_key in http_responses:
                response = http_responses[response_key]
                attack_data['http_status'] = response['status']
            
            # Load JSON data for this payload
            json_file = f"payload_{payload_id}_output.json"
            if json_file in json_outputs:
                attack_data['json_data'] = json_outputs[json_file]
            
            # Detect attack result
            detection_result = self.detect_attack(attack_type, attack_data)
            
            # Store result
            if attack_type not in results['attack_summary']:
                results['attack_summary'][attack_type] = {
                    'count': 0,
                    'successful': 0,
                    'failed': 0,
                    'success_rate': 0.0,
                    'details': []
                }
            
            results['attack_summary'][attack_type]['count'] += 1
            results['attack_summary'][attack_type]['details'].append({
                'payload_id': payload_id,
                'description': attack.get('DESCRIPTION', ''),
                'success': detection_result['success'],
                'confidence': detection_result['confidence'],
                'evidence': detection_result['evidence'],
                'http_status': attack_data['http_status']
            })
            
            if detection_result['success']:
                results['attack_summary'][attack_type]['successful'] += 1
                results['overall_stats']['successful_attacks'] += 1
            else:
                results['attack_summary'][attack_type]['failed'] += 1
                results['overall_stats']['failed_attacks'] += 1
            
            results['overall_stats']['total_attacks'] += 1
        
        # Calculate success rates
        if results['overall_stats']['total_attacks'] > 0:
            results['overall_stats']['success_rate'] = (
                results['overall_stats']['successful_attacks'] / 
                results['overall_stats']['total_attacks'] * 100
            )
        
        for attack_type in results['attack_summary']:
            summary = results['attack_summary'][attack_type]
            if summary['count'] > 0:
                summary['success_rate'] = (summary['successful'] / summary['count']) * 100
        
        return results
    
    def generate_report(self, results: Dict[str, Any],
                       output_file: Optional[str] = None) -> str:
        """Generate detailed attack detection report"""
        report = []
        report.append("=" * 60)
        report.append("ENHANCED ATTACK DETECTION REPORT")
        report.append("=" * 60)
        report.append(f"Timestamp: {results['timestamp']}")
        report.append("")
        
        # Overall statistics
        stats = results['overall_stats']
        report.append("OVERALL STATISTICS:")
        report.append(f"  Total Attacks: {stats['total_attacks']}")
        report.append(f"  Successful: {stats['successful_attacks']}")
        report.append(f"  Failed: {stats['failed_attacks']}")
        report.append(f"  Success Rate: {stats['success_rate']:.2f}%")
        report.append("")
        
        # Attack type breakdown
        report.append("ATTACK TYPE BREAKDOWN:")
        for attack_type, summary in results['attack_summary'].items():
            report.append(f"  {attack_type.upper()}:")
            report.append(f"    Count: {summary['count']}")
            report.append(f"    Successful: {summary['successful']}")
            report.append(f"    Failed: {summary['failed']}")
            report.append(f"    Success Rate: {summary['success_rate']:.2f}%")
            
            # Show details for successful attacks
            successful_details = [d for d in summary['details'] if d['success']]
            if successful_details:
                report.append("    Successful Attacks:")
                for detail in successful_details[:5]:  # Show first 5
                    report.append(f"      - Payload {detail['payload_id']}: {detail['description']}")
                    report.append(f"        Evidence: {', '.join(detail['evidence'])}")
                    report.append(f"        Confidence: {detail['confidence']:.2f}")
                    if detail['http_status']:
                        report.append(f"        HTTP Status: {detail['http_status']}")
            report.append("")
        
        report_text = "\n".join(report)
        
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report_text)
                print(f"Report saved to: {output_file}")
            except Exception as e:
                print(f"Warning: Could not write report to {output_file}: {e}")
        
        return report_text

def main():
    parser = argparse.ArgumentParser(description='Enhanced Attack Detection Engine')
    parser.add_argument('--rules', default='confs/attacker/detection_rules.yaml',
                       help='Path to detection rules YAML file')
    parser.add_argument('--attack-log', required=True,
                       help='Path to attack log file')
    parser.add_argument('--nginx-log', required=True,
                       help='Path to nginx log file')
    parser.add_argument('--json-output-dir', default='/tmp/sqlmap_attack',
                       help='Directory containing JSON outputs')
    parser.add_argument('--output', help='Output file for report')
    parser.add_argument('--json', help='Output JSON results to file')

    args = parser.parse_args()

    detector = AttackDetector(args.rules)
    results = detector.analyze_attack_results(args.attack_log, args.nginx_log, args.json_output_dir)
    report = detector.generate_report(results, args.output)
    print(report)

    if args.json:
        with open(args.json, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"JSON results saved to: {args.json}")

if __name__ == '__main__':
    main() 