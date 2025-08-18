#!/usr/bin/env python3
"""
WAF Simulation Log Parser
Parses simulated WAF logs from nginx with attack detection
"""

import re
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from .base_parser import BaseParser


class WafSimulationParser(BaseParser):
    """
    Parser for simulated WAF logs based on nginx logs
    Detects attack patterns and labels them accordingly
    """
    
    def _get_source_type(self) -> str:
        """Return the source type"""
        return "waf_simulation"
    
    def __init__(self, source_name: str = "waf_simulation"):
        super().__init__(source_name)
        # Initialize attack patterns for detection
        self.attack_patterns = {
            'sql_injection': [
                r"union\s+select",
                r"or\s+1\s*=\s*1",
                r"'\s*or\s*'",
                r"drop\s+table",
                r"select\s+\*\s+from",
                r"--\s*$",
                r";\s*select"
            ],
            'xss': [
                r"<script[^>]*>",
                r"javascript:",
                r"onerror\s*=",
                r"onload\s*=",
                r"alert\s*\(",
                r"<iframe"
            ],
            'path_traversal': [
                r"\.\./",
                r"\.\.\\",
                r"/etc/passwd"
            ]
        }
    
    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single nginx log line and detect attacks
        
        Args:
            line: Raw nginx log line
            
        Returns:
            Dict: Parsed data with WAF simulation info
        """
        try:
            # Use the existing nginx parser logic
            from .nginx_parser import NginxParser
            nginx_parser = NginxParser(self.source_name)
            parsed_data = nginx_parser.parse_line(line)
            
            if not parsed_data:
                return None
            
            # Add WAF simulation fields
            parsed_data['source_type'] = 'waf_simulation'
            
            # Check for attack patterns
            request_line = parsed_data.get('request_path', '') + ' ' + parsed_data.get('payload', '')
            attack_detected = False
            attack_type = None
            blocked = False
            
            for attack_name, patterns in self.attack_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, request_line, re.IGNORECASE):
                        attack_detected = True
                        attack_type = attack_name
                        # Simulate WAF blocking based on pattern
                        blocked = True
                        break
                if attack_detected:
                    break
            
            # Update fields based on detection
            if attack_detected:
                parsed_data['event_type'] = 'attack_blocked' if blocked else 'attack_detected'
                parsed_data['severity'] = 'HIGH'
                parsed_data['label'] = 'malicious'
                parsed_data['message'] = f"WAF: {attack_type} attack {'blocked' if blocked else 'detected'}"
                # Add WAF-specific fields
                parsed_data['waf_action'] = 'blocked' if blocked else 'allowed'
                parsed_data['attack_type'] = attack_type
                # Simulate response code change for blocked requests
                if blocked:
                    parsed_data['response_code'] = '403'
            else:
                # Normal traffic
                parsed_data['waf_action'] = 'allowed'
                parsed_data['attack_type'] = None
            
            return parsed_data
            
        except Exception as e:
            self.logger.error(f"Error parsing WAF simulation log line: {e}")
            return None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get parsing statistics with WAF simulation metrics"""
        stats = super().get_stats()
        
        # Add WAF simulation specific statistics
        stats.update({
            'attacks_blocked': 0,
            'attacks_detected': 0,
            'requests_allowed': 0,
            'attack_types': {
                'sql_injection': 0,
                'xss': 0,
                'path_traversal': 0
            }
        })
        
        return stats


# Register parser
def create_parser(source_name: str = "waf_simulation") -> WafSimulationParser:
    """Factory function to create WAF simulation parser"""
    return WafSimulationParser(source_name)
