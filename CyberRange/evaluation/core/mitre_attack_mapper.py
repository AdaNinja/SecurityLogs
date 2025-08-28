#!/usr/bin/env python3
"""
MITRE ATT&CK Framework Mapper
提供攻击技术到MITRE ATT&CK战术和技术的映射
"""

import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

class AttackPhase(Enum):
    """MITRE ATT&CK Tactics"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

@dataclass
class AttackSignature:
    """攻击签名定义"""
    name: str
    technique_id: str
    tactic: AttackPhase
    patterns: List[str]  # 正则表达式模式
    severity: str
    description: str
    indicators: List[str]  # 关键指标

@dataclass
class AttackEvent:
    """检测到的攻击事件"""
    timestamp: str
    technique_id: str
    tactic: AttackPhase
    severity: str
    confidence: float
    indicators: List[str]
    raw_data: Dict
    chain_id: Optional[str] = None  # 攻击链ID

class MITREAttackMapper:
    """MITRE ATT&CK映射器"""
    
    def __init__(self):
        self.attack_signatures = self._initialize_signatures()
        self.attack_chains = {}  # 存储检测到的攻击链
        
    def _initialize_signatures(self) -> List[AttackSignature]:
        """初始化攻击签名库"""
        signatures = [
            # T1190 - Exploit Public-Facing Application
            AttackSignature(
                name="SQL Injection",
                technique_id="T1190",
                tactic=AttackPhase.INITIAL_ACCESS,
                patterns=[
                    r"(?i)(union\s+select|1\s*=\s*1|'.*or.*'1'='1')",
                    r"(?i)(select.*from.*information_schema)",
                    r"(?i)(drop\s+table|delete\s+from)",
                    r"(?i)(exec|execute|sp_|xp_)"
                ],
                severity="HIGH",
                description="SQL injection attack detected",
                indicators=["sql_keywords", "union_select", "or_condition"]
            ),
            
            # T1059.007 - Command and Scripting Interpreter: JavaScript
            AttackSignature(
                name="Cross-Site Scripting (XSS)",
                technique_id="T1059.007",
                tactic=AttackPhase.EXECUTION,
                patterns=[
                    r"(?i)<script[^>]*>.*?</script>",
                    r"(?i)javascript:",
                    r"(?i)on(load|click|error|focus|blur)=",
                    r"(?i)alert\s*\(|confirm\s*\(|prompt\s*\(",
                    r"(?i)document\.(cookie|domain)"
                ],
                severity="MEDIUM",
                description="Cross-site scripting attack detected",
                indicators=["script_tag", "javascript_event", "alert_function"]
            ),
            
            # T1059.004 - Command and Scripting Interpreter: Unix Shell
            AttackSignature(
                name="Command Injection",
                technique_id="T1059.004",
                tactic=AttackPhase.EXECUTION,
                patterns=[
                    r"(?i);.*?(cat|ls|pwd|whoami|id)",
                    r"(?i)\|\s*(cat|ls|pwd|whoami|id)",
                    r"(?i)`.*?(cat|ls|pwd|whoami|id)",
                    r"(?i)\$\(.*?(cat|ls|pwd|whoami|id)"
                ],
                severity="HIGH",
                description="Command injection attack detected",
                indicators=["shell_commands", "command_chaining", "execution_chars"]
            ),
            
            # T1083 - File and Directory Discovery
            AttackSignature(
                name="Directory Traversal",
                technique_id="T1083",
                tactic=AttackPhase.DISCOVERY,
                patterns=[
                    r"\.\.\/+",
                    r"\.\.\\+",
                    r"(?i)(etc\/passwd|etc\/shadow)",
                    r"(?i)(windows\/system32|winnt\/system32)",
                    r"(?i)%2e%2e%2f"
                ],
                severity="MEDIUM",
                description="Directory traversal attack detected",
                indicators=["path_traversal", "system_files", "encoded_traversal"]
            ),
            
            # T1078 - Valid Accounts
            AttackSignature(
                name="Authentication Bypass",
                technique_id="T1078",
                tactic=AttackPhase.CREDENTIAL_ACCESS,
                patterns=[
                    r"(?i)admin.*admin",
                    r"(?i)password.*password",
                    r"(?i)'.*or.*'1'='1'",
                    r"(?i)(bypass|skip).*auth"
                ],
                severity="HIGH",
                description="Authentication bypass attempt detected",
                indicators=["weak_credentials", "sql_auth_bypass", "auth_manipulation"]
            ),
            
            # T1083 - File and Directory Discovery
            AttackSignature(
                name="File Discovery",
                technique_id="T1083",
                tactic=AttackPhase.DISCOVERY,
                patterns=[
                    r"(?i)(robots\.txt|sitemap\.xml)",
                    r"(?i)(\.git|\.svn|\.env)",
                    r"(?i)(backup|config|admin)",
                    r"(?i)(phpinfo|test|debug)"
                ],
                severity="LOW",
                description="File discovery attempt detected",
                indicators=["sensitive_files", "config_files", "backup_files"]
            ),
            
            # T1046 - Network Service Scanning
            AttackSignature(
                name="HTTP Method Enumeration",
                technique_id="T1046",
                tactic=AttackPhase.DISCOVERY,
                patterns=[
                    r"(?i)(OPTIONS|HEAD|TRACE|CONNECT)",
                    r"(?i)(PUT|DELETE|PATCH)"
                ],
                severity="LOW",
                description="HTTP method enumeration detected",
                indicators=["http_methods", "service_discovery"]
            ),
            
            # T1548 - Abuse Elevation Control Mechanism
            AttackSignature(
                name="Privilege Escalation",
                technique_id="T1548",
                tactic=AttackPhase.PRIVILEGE_ESCALATION,
                patterns=[
                    r"(?i)\/admin\/",
                    r"(?i)\/root\/",
                    r"(?i)application-configuration",
                    r"(?i)(sudo|su\s+)"
                ],
                severity="HIGH",
                description="Privilege escalation attempt detected",
                indicators=["admin_paths", "config_access", "elevation_commands"]
            )
        ]
        return signatures
    
    def analyze_http_request(self, method: str, path: str, user_agent: str, 
                           payload: str, timestamp: str, status_code: int) -> List[AttackEvent]:
        """分析HTTP请求并检测攻击"""
        events = []
        
        # 组合所有要分析的文本
        combined_text = f"{method} {path} {payload}".lower()
        
        for signature in self.attack_signatures:
            confidence = 0.0
            detected_indicators = []
            
            # 检查每个模式
            for pattern in signature.patterns:
                if re.search(pattern, combined_text):
                    confidence += 1.0 / len(signature.patterns)
                    detected_indicators.append(pattern)
            
            # 如果检测到攻击
            if confidence > 0:
                # 根据状态码调整置信度
                if status_code >= 400:
                    confidence *= 1.2  # 错误状态码增加置信度
                elif status_code == 200:
                    confidence *= 0.8  # 成功状态码降低置信度
                
                # 根据User-Agent调整置信度
                if "advanced-attack-tool" in user_agent.lower():
                    confidence *= 1.5  # 高级攻击工具增加置信度
                elif "attacker" in user_agent.lower():
                    confidence *= 1.3  # 攻击者标识增加置信度
                
                confidence = min(confidence, 1.0)  # 限制最大置信度
                
                if confidence >= 0.3:  # 最小置信度阈值
                    event = AttackEvent(
                        timestamp=timestamp,
                        technique_id=signature.technique_id,
                        tactic=signature.tactic,
                        severity=signature.severity,
                        confidence=confidence,
                        indicators=detected_indicators,
                        raw_data={
                            'method': method,
                            'path': path,
                            'user_agent': user_agent,
                            'payload': payload,
                            'status_code': status_code
                        }
                    )
                    events.append(event)
        
        return events
    
    def detect_attack_chains(self, events: List[AttackEvent], 
                           time_window: int = 300) -> Dict[str, List[AttackEvent]]:
        """检测攻击链（时间窗口内的相关攻击）"""
        chains = {}
        
        # 按时间排序事件
        sorted_events = sorted(events, key=lambda x: x.timestamp)
        
        for i, event in enumerate(sorted_events):
            chain_id = None
            
            # 查找时间窗口内的前序事件
            for j in range(max(0, i-10), i):  # 检查前10个事件
                prev_event = sorted_events[j]
                time_diff = self._time_difference(prev_event.timestamp, event.timestamp)
                
                if time_diff <= time_window:
                    # 检查是否是攻击链的一部分
                    if self._is_chain_continuation(prev_event, event):
                        if prev_event.chain_id:
                            chain_id = prev_event.chain_id
                        else:
                            chain_id = f"chain_{i}_{j}"
                            prev_event.chain_id = chain_id
                            if chain_id not in chains:
                                chains[chain_id] = []
                            chains[chain_id].append(prev_event)
                        break
            
            if not chain_id:
                chain_id = f"single_{i}"
                chains[chain_id] = []
            
            event.chain_id = chain_id
            chains[chain_id].append(event)
        
        return chains
    
    def _is_chain_continuation(self, prev_event: AttackEvent, 
                             current_event: AttackEvent) -> bool:
        """判断是否是攻击链的延续"""
        # 高级攻击工具的请求更可能是链式攻击
        if ("advanced-attack-tool" in prev_event.raw_data.get('user_agent', '').lower() and
            "advanced-attack-tool" in current_event.raw_data.get('user_agent', '').lower()):
            return True
        
        # 特定的攻击序列模式
        chain_patterns = [
            # 认证后的权限提升
            (AttackPhase.CREDENTIAL_ACCESS, AttackPhase.PRIVILEGE_ESCALATION),
            # 发现后的利用
            (AttackPhase.DISCOVERY, AttackPhase.INITIAL_ACCESS),
            # 初始访问后的执行
            (AttackPhase.INITIAL_ACCESS, AttackPhase.EXECUTION),
            # 执行后的权限提升
            (AttackPhase.EXECUTION, AttackPhase.PRIVILEGE_ESCALATION)
        ]
        
        for prev_phase, next_phase in chain_patterns:
            if prev_event.tactic == prev_phase and current_event.tactic == next_phase:
                return True
        
        return False
    
    def _time_difference(self, time1: str, time2: str) -> int:
        """计算两个时间戳之间的差异（秒）"""
        from datetime import datetime
        try:
            dt1 = datetime.fromisoformat(time1.replace('Z', '+00:00'))
            dt2 = datetime.fromisoformat(time2.replace('Z', '+00:00'))
            return abs((dt2 - dt1).total_seconds())
        except:
            return 0
    
    def generate_enhanced_labels(self, events: List[AttackEvent]) -> Dict:
        """生成增强的标签信息"""
        chains = self.detect_attack_chains(events)
        
        labels = {
            'binary_label': 1 if events else 0,
            'attack_techniques': [event.technique_id for event in events],
            'attack_tactics': [event.tactic.value for event in events],
            'severity_max': max([event.severity for event in events], default="NONE"),
            'confidence_avg': sum([event.confidence for event in events]) / len(events) if events else 0.0,
            'attack_chains': len(chains),
            'chain_details': {
                chain_id: {
                    'techniques': [e.technique_id for e in chain_events],
                    'tactics': [e.tactic.value for e in chain_events],
                    'duration': self._chain_duration(chain_events)
                }
                for chain_id, chain_events in chains.items()
            },
            'indicators': [indicator for event in events for indicator in event.indicators]
        }
        
        return labels
    
    def _chain_duration(self, chain_events: List[AttackEvent]) -> float:
        """计算攻击链持续时间"""
        if len(chain_events) < 2:
            return 0.0
        
        timestamps = [event.timestamp for event in chain_events]
        timestamps.sort()
        
        return self._time_difference(timestamps[0], timestamps[-1])

if __name__ == "__main__":
    # 测试代码
    mapper = MITREAttackMapper()
    
    # 模拟测试
    test_events = mapper.analyze_http_request(
        method="GET",
        path="/rest/products/search?q=<script>alert('XSS')</script>",
        user_agent="attacker",
        payload="GET /rest/products/search?q=<script>alert('XSS')</script> HTTP/1.1",
        timestamp="2025-08-27T21:48:13.000000Z",
        status_code=500
    )
    
    for event in test_events:
        print(f"检测到攻击: {event.technique_id} - {event.tactic.value} (置信度: {event.confidence:.2f})")
