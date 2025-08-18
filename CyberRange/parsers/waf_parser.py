#!/usr/bin/env python3
"""
ModSecurity WAF Log Parser
Parses ModSecurity audit logs in JSON format
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from .base_parser import BaseParser


class WafParser(BaseParser):
    """
    Parser for ModSecurity WAF audit logs
    Handles JSON format audit logs from ModSecurity
    """
    
    def _get_source_type(self) -> str:
        """Return the source type"""
        return "waf"
    
    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single ModSecurity audit log line (JSON format)
        
        Args:
            line: Raw JSON log line from ModSecurity
            
        Returns:
            Dict: Parsed data or None if parsing failed
        """
        try:
            line = line.strip()
            if not line:
                return None
            
            # Parse JSON audit log
            audit_data = json.loads(line)
            
            # Extract transaction info
            transaction = audit_data.get('transaction', {})
            
            # Extract basic request info
            request = transaction.get('request', {})
            response = transaction.get('response', {})
            
            # Extract timestamp
            timestamp_str = transaction.get('time_stamp', '')
            timestamp = self.normalize_timestamp(timestamp_str) if timestamp_str else datetime.utcnow().strftime(self.TIMESTAMP_FORMAT)
            
            # Extract source and destination IPs
            client_ip = request.get('headers', {}).get('Host', [''])[0] if isinstance(request.get('headers', {}).get('Host'), list) else request.get('headers', {}).get('Host', '')
            server_ip = transaction.get('server_id', '')
            
            # Extract request details
            method = request.get('method', '')
            uri = request.get('uri', '')
            protocol = request.get('http_version', '')
            
            # Extract response details
            status_code = response.get('http_code', 0)
            
            # Extract WAF-specific data
            messages = transaction.get('messages', [])
            blocked = any(msg.get('data', {}).get('action') == 'deny' for msg in messages)
            
            # Extract rule information
            rule_ids = []
            rule_messages = []
            severity_scores = []
            
            for message in messages:
                rule_id = message.get('details', {}).get('ruleId', '')
                rule_msg = message.get('message', '')
                severity = message.get('details', {}).get('severity', '')
                
                if rule_id:
                    rule_ids.append(rule_id)
                if rule_msg:
                    rule_messages.append(rule_msg)
                if severity:
                    severity_scores.append(severity)
            
            # Determine event type and severity
            if blocked:
                event_type = "attack_blocked"
                severity = "HIGH"
                label = "malicious"
            elif rule_ids:
                event_type = "attack_detected"
                severity = "MEDIUM"
                label = "suspicious"
            else:
                event_type = "request_allowed"
                severity = "INFO"
                label = "benign"
            
            # Extract user agent
            user_agent = ''
            headers = request.get('headers', {})
            if 'User-Agent' in headers:
                user_agent = headers['User-Agent'][0] if isinstance(headers['User-Agent'], list) else headers['User-Agent']
            
            # Build message
            if rule_messages:
                message = f"WAF {event_type}: {', '.join(rule_messages[:3])}"  # Limit to first 3 messages
            else:
                message = f"WAF {event_type}: {method} {uri}"
            
            # Extract payload (limited for performance)
            payload = ""
            if 'body' in request:
                body = request['body']
                if isinstance(body, str):
                    payload = body[:500]  # Limit payload size
                elif isinstance(body, dict):
                    payload = json.dumps(body)[:500]
            
            # Create parsed record
            parsed_data = {
                'timestamp': timestamp,
                'source_type': self.source_type,
                'source_name': self.source_name,
                'event_type': event_type,
                'severity': severity,
                'message': message,
                'ip_src': client_ip,
                'ip_dst': server_ip,
                'port_src': request.get('port_src', ''),
                'port_dst': request.get('port_dst', ''),
                'protocol': protocol,
                'user_agent': user_agent,
                'request_method': method,
                'request_path': uri,
                'response_code': str(status_code),
                'payload': payload,
                'label': label,
                # WAF-specific fields
                'waf_action': 'blocked' if blocked else 'allowed',
                'rule_ids': ','.join(rule_ids),
                'anomaly_score': transaction.get('anomaly_score', 0),
                'sql_injection_score': transaction.get('sql_injection_score', 0),
                'xss_score': transaction.get('xss_score', 0)
            }
            
            return parsed_data
            
        except json.JSONDecodeError as e:
            self.logger.warning(f"Failed to parse JSON audit log: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error parsing WAF log line: {e}")
            return None
    
    def _load_attack_patterns(self) -> List[str]:
        """Load WAF-specific attack patterns"""
        return [
            # SQL Injection patterns
            r"union\s+select",
            r"or\s+1\s*=\s*1",
            r"'\s*or\s*'",
            r"drop\s+table",
            r"exec\s*\(",
            
            # XSS patterns
            r"<script[^>]*>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"alert\s*\(",
            
            # Path traversal patterns
            r"\.\./",
            r"\.\.\\",
            r"/etc/passwd",
            r"windows\\system32",
            
            # Command injection patterns
            r";\s*cat\s+",
            r";\s*ls\s+",
            r";\s*ping\s+",
            r"\|\s*nc\s+",
            
            # Generic malicious patterns
            r"eval\s*\(",
            r"base64_decode",
            r"exec\s*\(",
            r"system\s*\("
        ]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get parsing statistics with WAF-specific metrics"""
        stats = super().get_stats()
        
        # Add WAF-specific statistics
        stats.update({
            'attacks_blocked': 0,
            'attacks_detected': 0,
            'requests_allowed': 0,
            'top_rule_ids': {},
            'anomaly_score_distribution': {
                'low': 0,     # 0-2
                'medium': 0,  # 3-4
                'high': 0,    # 5+
            }
        })
        
        return stats


# Register parser
def create_parser(source_name: str = "modsecurity") -> WafParser:
    """Factory function to create WAF parser"""
    return WafParser(source_name)
