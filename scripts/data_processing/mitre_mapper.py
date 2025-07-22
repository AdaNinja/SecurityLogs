#!/usr/bin/env python3
"""
MITRE ATT&CK Mapper for SecurityLogs
Maps attack behaviors to MITRE ATT&CK techniques and tactics
"""

import re
import json
from typing import Dict, Any, List, Optional
from datetime import datetime

class MITREMapper:
    """MITRE ATT&CK mapping utility"""
    
    def __init__(self):
        # MITRE ATT&CK技术映射数据库
        self.technique_mappings = {
            # 侦察阶段 (Reconnaissance)
            "network_scan": {
                "tactic": "Reconnaissance",
                "technique": "T1595",
                "technique_name": "Active Scanning",
                "sub_technique": "T1595.002",
                "sub_technique_name": "Port Scanning",
                "confidence": "high"
            },
            "host_discovery": {
                "tactic": "Reconnaissance", 
                "technique": "T1595",
                "technique_name": "Active Scanning",
                "sub_technique": "T1595.001",
                "sub_technique_name": "Scanning IP Blocks",
                "confidence": "high"
            },
            "web_enumeration": {
                "tactic": "Reconnaissance",
                "technique": "T1595",
                "technique_name": "Active Scanning", 
                "sub_technique": "T1595.004",
                "sub_technique_name": "Vulnerability Scanning",
                "confidence": "high"
            },
            
            # 初始访问 (Initial Access)
            "sql_injection": {
                "tactic": "Initial Access",
                "technique": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "sub_technique": "T1190.001",
                "sub_technique_name": "SQL Injection",
                "confidence": "high"
            },
            "login_bruteforce": {
                "tactic": "Initial Access",
                "technique": "T1110",
                "technique_name": "Brute Force",
                "sub_technique": "T1110.001", 
                "sub_technique_name": "Password Guessing",
                "confidence": "medium"
            },
            
            # 执行 (Execution)
            "command_injection": {
                "tactic": "Execution",
                "technique": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "sub_technique": "T1059.004",
                "sub_technique_name": "Unix Shell",
                "confidence": "high"
            },
            
            # 持久化 (Persistence)
            "backdoor": {
                "tactic": "Persistence",
                "technique": "T1098",
                "technique_name": "Account Manipulation",
                "sub_technique": "T1098.001",
                "sub_technique_name": "Additional Cloud Credentials",
                "confidence": "medium"
            },
            
            # 权限提升 (Privilege Escalation)
            "privilege_escalation": {
                "tactic": "Privilege Escalation",
                "technique": "T1068",
                "technique_name": "Exploitation for Privilege Escalation",
                "sub_technique": "",
                "sub_technique_name": "",
                "confidence": "medium"
            },
            
            # 防御规避 (Defense Evasion)
            "log_deletion": {
                "tactic": "Defense Evasion",
                "technique": "T1070",
                "technique_name": "Indicator Removal on Host",
                "sub_technique": "T1070.001",
                "sub_technique_name": "Clear Windows Event Logs",
                "confidence": "medium"
            },
            
            # 凭据访问 (Credential Access)
            "password_dump": {
                "tactic": "Credential Access",
                "technique": "T1003",
                "technique_name": "OS Credential Dumping",
                "sub_technique": "T1003.001",
                "sub_technique_name": "LSASS Memory",
                "confidence": "high"
            },
            
            # 发现 (Discovery)
            "process_discovery": {
                "tactic": "Discovery",
                "technique": "T1057",
                "technique_name": "Process Discovery",
                "sub_technique": "",
                "sub_technique_name": "",
                "confidence": "medium"
            },
            "file_discovery": {
                "tactic": "Discovery",
                "technique": "T1083",
                "technique_name": "File and Directory Discovery",
                "sub_technique": "",
                "sub_technique_name": "",
                "confidence": "medium"
            },
            
            # 横向移动 (Lateral Movement)
            "remote_execution": {
                "tactic": "Lateral Movement",
                "technique": "T1021",
                "technique_name": "Remote Services",
                "sub_technique": "T1021.001",
                "sub_technique_name": "Remote Desktop Protocol",
                "confidence": "medium"
            },
            
            # 收集 (Collection)
            "data_staged": {
                "tactic": "Collection",
                "technique": "T1074",
                "technique_name": "Data Staged",
                "sub_technique": "T1074.001",
                "sub_technique_name": "Local Data Staging",
                "confidence": "medium"
            },
            
            # 命令与控制 (Command and Control)
            "dns_tunneling": {
                "tactic": "Command and Control",
                "technique": "T1071",
                "technique_name": "Application Layer Protocol",
                "sub_technique": "T1071.004",
                "sub_technique_name": "DNS",
                "confidence": "high"
            },
            
            # 渗出 (Exfiltration)
            "data_exfiltration": {
                "tactic": "Exfiltration",
                "technique": "T1041",
                "technique_name": "Exfiltration Over C2 Channel",
                "sub_technique": "",
                "sub_technique_name": "",
                "confidence": "medium"
            }
        }
        
        # 攻击链模式
        self.attack_chains = {
            "sql_injection_chain": [
                "T1595.002",  # Port Scanning
                "T1595.004",  # Vulnerability Scanning  
                "T1190.001",  # SQL Injection
                "T1005",      # Data from Local System
                "T1041"       # Exfiltration Over C2 Channel
            ],
            "web_attack_chain": [
                "T1595.002",  # Port Scanning
                "T1595.004",  # Vulnerability Scanning
                "T1190.001",  # SQL Injection
                "T1059.004",  # Unix Shell
                "T1003.001",  # LSASS Memory
                "T1041"       # Exfiltration Over C2 Channel
            ]
        }
    
    def map_attack_pattern(self, event_type: str, details: Dict[str, Any], 
                          source_type: str = None) -> Optional[Dict[str, Any]]:
        """Map attack pattern to MITRE ATT&CK technique"""
        
        # 基于事件类型进行初步映射
        if event_type in self.technique_mappings:
            mapping = self.technique_mappings[event_type].copy()
            
            # 根据详细信息调整置信度
            mapping["confidence"] = self._adjust_confidence(mapping["confidence"], details)
            
            # 添加攻击链信息
            mapping["attack_chain"] = self._get_attack_chain(event_type, details)
            
            return mapping
        
        # 基于日志内容进行模式匹配
        return self._pattern_based_mapping(details, source_type)
    
    def _pattern_based_mapping(self, details: Dict[str, Any], source_type: str) -> Optional[Dict[str, Any]]:
        """基于模式匹配的MITRE映射"""
        
        raw_content = details.get("raw", "").lower()
        
        # SQL注入模式
        sql_patterns = [
            r"union\s+select", r"or\s+1\s*=\s*1", r"admin'", r"drop\s+table",
            r"insert\s+into", r"select\s*\*\s+from", r"';?\s*drop"
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, raw_content, re.IGNORECASE):
                mapping = self.technique_mappings["sql_injection"].copy()
                mapping["confidence"] = "high"
                mapping["attack_chain"] = self.attack_chains["sql_injection_chain"]
                return mapping
        
        # 端口扫描模式
        scan_patterns = [
            r"nmap", r"port\s+scan", r"tcp\s+scan", r"syn\s+scan",
            r"open\s+port", r"closed\s+port"
        ]
        
        for pattern in scan_patterns:
            if re.search(pattern, raw_content, re.IGNORECASE):
                mapping = self.technique_mappings["network_scan"].copy()
                mapping["confidence"] = "medium"
                return mapping
        
        # 暴力破解模式
        brute_patterns = [
            r"brute\s+force", r"password\s+guess", r"login\s+attempt",
            r"failed\s+login", r"invalid\s+password"
        ]
        
        for pattern in brute_patterns:
            if re.search(pattern, raw_content, re.IGNORECASE):
                mapping = self.technique_mappings["login_bruteforce"].copy()
                mapping["confidence"] = "medium"
                return mapping
        
        # DNS隧道模式
        dns_patterns = [
            r"dns\s+tunnel", r"base64", r"hex\s+encoded",
            r"suspicious\s+dns", r"long\s+dns\s+query"
        ]
        
        for pattern in dns_patterns:
            if re.search(pattern, raw_content, re.IGNORECASE):
                mapping = self.technique_mappings["dns_tunneling"].copy()
                mapping["confidence"] = "high"
                return mapping
        
        return None
    
    def _adjust_confidence(self, base_confidence: str, details: Dict[str, Any]) -> str:
        """根据详细信息调整置信度"""
        
        # 如果有明确的攻击标识，提高置信度
        if details.get("is_attack"):
            if base_confidence == "medium":
                return "high"
            elif base_confidence == "low":
                return "medium"
        
        # 如果有详细的攻击载荷，提高置信度
        if details.get("payload") or details.get("attack_payload"):
            if base_confidence == "low":
                return "medium"
        
        return base_confidence
    
    def _get_attack_chain(self, event_type: str, details: Dict[str, Any]) -> List[str]:
        """获取攻击链技术序列"""
        
        # 根据事件类型返回预定义的攻击链
        if event_type == "sql_injection":
            return self.attack_chains["sql_injection_chain"]
        elif event_type in ["network_scan", "web_enumeration"]:
            return self.attack_chains["web_attack_chain"]
        
        # 默认返回空列表
        return []
    
    def get_technique_info(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """根据技术ID获取详细信息"""
        
        for mapping in self.technique_mappings.values():
            if mapping["technique"] == technique_id:
                return mapping
        
        return None
    
    def get_tactic_techniques(self, tactic: str) -> List[Dict[str, Any]]:
        """获取指定战术的所有技术"""
        
        techniques = []
        for mapping in self.technique_mappings.values():
            if mapping["tactic"] == tactic:
                techniques.append(mapping)
        
        return techniques

def main():
    """测试MITRE映射器"""
    mapper = MITREMapper()
    
    # 测试SQL注入映射
    test_details = {
        "raw": "SQL injection attempt: admin' OR '1'='1",
        "payload": "admin' OR '1'='1",
        "is_attack": True
    }
    
    result = mapper.map_attack_pattern("sql_injection", test_details)
    print("SQL Injection Mapping:")
    print(json.dumps(result, indent=2))
    
    # 测试模式匹配
    pattern_details = {
        "raw": "Port scan detected: nmap -sS 192.168.1.1",
        "is_attack": True
    }
    
    result = mapper._pattern_based_mapping(pattern_details, "network")
    print("\nPattern-based Mapping:")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main() 