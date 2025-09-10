#!/usr/bin/env python3
"""
Attack Log Parser
Parses attack logs and outputs unified CSV format
"""

import re
from typing import Dict, Optional, Any
from base_parser import BaseParser


class AttackParser(BaseParser):
    """
    Parser for attack logs
    Extracts attack information and payload details
    """
    
    def _get_source_type(self) -> str:
        return "attack"
    
    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse attack log line
        
        Expected formats:
        - JSON: {"timestamp": "...", "level": "...", "message": "...", "source": "attacker", ...}
        - Standard: [timestamp] ATTACK_TYPE: description - payload
        - Detailed: [timestamp] ATTACK_TYPE: method path - payload (result)
        
        Returns:
            Dict: Parsed data or None if parsing failed
        """
        try:
            # Try JSON format first
            if line.strip().startswith('{') and line.strip().endswith('}'):
                return self._parse_json_attack(line)
            # Try different attack log formats
            elif 'ATTACK_TYPE:' in line:
                return self._parse_standard_attack(line)
            elif 'SQL injection' in line or 'XSS' in line or 'CSRF' in line:
                return self._parse_detailed_attack(line)
            elif 'PAYLOAD_ID:' in line:
                return self._parse_payload_attack(line)
            else:
                return None
                
        except Exception as e:
            self.logger.warning(f"Failed to parse attack line: {e}")
            return None
    
    def _parse_json_attack(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse JSON format attack log"""
        try:
            import json
            
            # Parse JSON
            data = json.loads(line.strip())
            
            # Extract basic information
            timestamp = data.get('timestamp', '')
            level = data.get('level', 'INFO')
            message = data.get('message', '')
            source_ip = data.get('ip', '')
            
            # Normalize timestamp
            normalized_timestamp = self.normalize_timestamp(timestamp)
            
            # Extract attack-specific information
            payload_id = data.get('payload_id', '')
            attack_type = data.get('attack_type', '')
            tool = data.get('tool', '')
            description = data.get('description', '')
            method = data.get('method', '')
            path = data.get('path', '')
            result = data.get('result', '')
            http_code = data.get('http_code', '')
            event_type = data.get('event_type', 'attack')
            
            # Determine severity based on level and result
            if level == 'ERROR' or result == 'FAILED':
                severity = 'error'
            elif level == 'WARNING':
                severity = 'warning'
            else:
                severity = 'info'
            
            # Detect attack patterns
            label = self.detect_attack(description + ' ' + message)
            
            return {
                'timestamp': normalized_timestamp,
                'source_type': self.source_type,
                'source_name': self.source_name,
                'event_type': event_type,
                'severity': severity,
                'message': message,
                'ip_src': source_ip,
                'ip_dst': '',
                'port_src': '',
                'port_dst': '',
                'protocol': '',
                'user_agent': '',
                'request_method': method,
                'request_path': path,
                'response_code': http_code,
                'payload': description,
                'label': label
            }
            
        except json.JSONDecodeError:
            return None
        except Exception as e:
            self.logger.warning(f"Failed to parse JSON attack line: {e}")
            return None
    
    def _parse_standard_attack(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse standard attack log format"""
        try:
            # Pattern: [timestamp] ATTACK_TYPE: description - payload
            pattern = r'\[([^\]]+)\]\s+(\w+):\s*(.+?)\s*-\s*(.+)'
            match = re.match(pattern, line)
            
            if not match:
                return None
            
            timestamp_str, attack_type, description, payload = match.groups()
            
            # Normalize timestamp
            normalized_timestamp = self.normalize_timestamp(timestamp_str)
            
            # Determine severity
            severity = "error"  # Attacks are typically high severity
            
            # Detect attack patterns
            label = self.detect_attack(payload)
            
            return {
                'timestamp': normalized_timestamp,
                'source_type': self.source_type,
                'source_name': self.source_name,
                'event_type': 'attack',
                'severity': severity,
                'message': f"{attack_type}: {description}",
                'ip_src': '',
                'ip_dst': '',
                'port_src': '',
                'port_dst': '',
                'protocol': '',
                'user_agent': '',
                'request_method': '',
                'request_path': '',
                'response_code': '',
                'payload': payload,
                'label': label
            }
            
        except Exception:
            return None
    
    def _parse_detailed_attack(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse detailed attack log format"""
        try:
            # Pattern: [timestamp] ATTACK_TYPE: method path - payload (result)
            pattern = r'\[([^\]]+)\]\s+(\w+):\s*(\w+)\s+([^\s]+)\s*-\s*(.+?)\s*\(([^)]+)\)'
            match = re.match(pattern, line)
            
            if not match:
                return None
            
            timestamp_str, attack_type, method, path, payload, result = match.groups()
            
            # Normalize timestamp
            normalized_timestamp = self.normalize_timestamp(timestamp_str)
            
            # Determine severity based on result
            severity = "error" if result.lower() in ['success', 'blocked'] else "warning"
            
            # Detect attack patterns
            label = self.detect_attack(payload)
            
            return {
                'timestamp': normalized_timestamp,
                'source_type': self.source_type,
                'source_name': self.source_name,
                'event_type': 'attack',
                'severity': severity,
                'message': f"{attack_type}: {method} {path}",
                'ip_src': '',
                'ip_dst': '',
                'port_src': '',
                'port_dst': '',
                'protocol': 'HTTP',
                'user_agent': '',
                'request_method': method,
                'request_path': path,
                'response_code': '',
                'payload': payload,
                'label': label
            }
            
        except Exception:
            return None
    
    def _parse_payload_attack(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse payload-based attack log format"""
        try:
            # Extract payload ID and attack type
            payload_match = re.search(r'PAYLOAD_ID:\s*(\d+)', line)
            attack_type_match = re.search(r'ATTACK_TYPE:\s*(\w+)', line)
            description_match = re.search(r'DESCRIPTION:\s*(.+)', line)
            
            if not payload_match or not attack_type_match:
                return None
            
            payload_id = payload_match.group(1)
            attack_type = attack_type_match.group(1)
            description = description_match.group(1) if description_match else ""
            
            # Extract timestamp if present
            timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
            if timestamp_match:
                timestamp_str = timestamp_match.group(1)
                normalized_timestamp = self.normalize_timestamp(timestamp_str)
            else:
                normalized_timestamp = self.get_current_timestamp()
            
            # Determine severity
            severity = "error"
            
            # Detect attack patterns
            label = self.detect_attack(description)
            
            return {
                'timestamp': normalized_timestamp,
                'source_type': self.source_type,
                'source_name': self.source_name,
                'event_type': 'attack',
                'severity': severity,
                'message': f"{attack_type}: {description}",
                'ip_src': '',
                'ip_dst': '',
                'port_src': '',
                'port_dst': '',
                'protocol': '',
                'user_agent': '',
                'request_method': '',
                'request_path': '',
                'response_code': '',
                'payload': f"payload_{payload_id}",
                'label': label
            }
            
        except Exception:
            return None 