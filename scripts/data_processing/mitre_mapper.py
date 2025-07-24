#!/usr/bin/env python3
"""
MITRE ATT&CK Framework Mapper
Maps security events to MITRE ATT&CK techniques
"""

class MITREMapper:
    def __init__(self):
        self.technique_mapping = {
            # Reconnaissance
            'nmap_scan': {'technique_id': 'T1046', 'technique_name': 'Network Service Discovery'},
            'dirb_scan': {'technique_id': 'T1083', 'technique_name': 'File and Directory Discovery'},
            'nikto_scan': {'technique_id': 'T1046', 'technique_name': 'Network Service Discovery'},
            
            # Initial Access
            'sql_injection': {'technique_id': 'T1190', 'technique_name': 'Exploit Public-Facing Application'},
            'login_bypass': {'technique_id': 'T1078', 'technique_name': 'Valid Accounts'},
            
            # Execution
            'command_injection': {'technique_id': 'T1059', 'technique_name': 'Command and Scripting Interpreter'},
            
            # Persistence
            'backdoor': {'technique_id': 'T1098', 'technique_name': 'Account Manipulation'},
            
            # Privilege Escalation
            'privilege_escalation': {'technique_id': 'T1068', 'technique_name': 'Exploitation for Privilege Escalation'},
            
            # Defense Evasion
            'log_deletion': {'technique_id': 'T1070', 'technique_name': 'Indicator Removal on Host'},
            
            # Credential Access
            'password_dump': {'technique_id': 'T1003', 'technique_name': 'OS Credential Dumping'},
            
            # Discovery
            'system_info': {'technique_id': 'T1082', 'technique_name': 'System Information Discovery'},
            'network_discovery': {'technique_id': 'T1046', 'technique_name': 'Network Service Discovery'},
            
            # Lateral Movement
            'remote_execution': {'technique_id': 'T1021', 'technique_name': 'Remote Services'},
            
            # Collection
            'data_staged': {'technique_id': 'T1074', 'technique_name': 'Data Staged'},
            
            # Command and Control
            'dns_tunneling': {'technique_id': 'T1071', 'technique_name': 'Application Layer Protocol'},
            'http_tunneling': {'technique_id': 'T1071', 'technique_name': 'Application Layer Protocol'},
            
            # Exfiltration
            'data_exfiltration': {'technique_id': 'T1041', 'technique_name': 'Exfiltration Over C2 Channel'},
            
            # Impact
            'data_destruction': {'technique_id': 'T1485', 'technique_name': 'Data Destruction'},
        }
    
    def map_attack_pattern(self, event_type, details, source_type):
        """
        Map an event to MITRE ATT&CK technique
        
        Args:
            event_type (str): Type of security event
            details (dict): Event details
            source_type (str): Source of the event
            
        Returns:
            dict: MITRE ATT&CK mapping or None
        """
        # Direct mapping
        if event_type in self.technique_mapping:
            return self.technique_mapping[event_type]
        
        # Pattern-based mapping
        event_lower = event_type.lower()
        
        if 'scan' in event_lower or 'recon' in event_lower:
            return {'technique_id': 'T1046', 'technique_name': 'Network Service Discovery'}
        elif 'injection' in event_lower:
            return {'technique_id': 'T1190', 'technique_name': 'Exploit Public-Facing Application'}
        elif 'login' in event_lower or 'auth' in event_lower:
            return {'technique_id': 'T1078', 'technique_name': 'Valid Accounts'}
        elif 'dns' in event_lower:
            return {'technique_id': 'T1071', 'technique_name': 'Application Layer Protocol'}
        elif 'exfil' in event_lower or 'data' in event_lower:
            return {'technique_id': 'T1041', 'technique_name': 'Exfiltration Over C2 Channel'}
        else:
            # Default mapping for unknown events
            return {'technique_id': 'T1190', 'technique_name': 'Exploit Public-Facing Application'}