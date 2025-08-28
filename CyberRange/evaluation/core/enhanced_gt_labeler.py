#!/usr/bin/env python3
"""
Enhanced Ground Truth Labeler
多阶段链式标签管道，结合事件中心注释和MITRE ATT&CK阶段映射
"""

import csv
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
import pandas as pd
from pathlib import Path

from .mitre_attack_mapper import MITREAttackMapper, AttackEvent, AttackPhase

@dataclass
class EnhancedLabel:
    """增强的Ground Truth标签"""
    timestamp: str
    binary_label: int  # 0=benign, 1=malicious
    attack_techniques: List[str]  # MITRE ATT&CK技术ID
    attack_tactics: List[str]    # MITRE ATT&CK战术
    attack_chain_id: Optional[str]  # 攻击链ID
    event_context: Dict[str, Any]  # 事件上下文信息
    behavioral_indicators: List[str]  # 行为指标
    kill_chain_phase: str       # Kill Chain阶段
    target_asset: str           # 目标资产

class EnhancedGTLabeler:
    """增强的Ground Truth标签生成器"""
    
    def __init__(self, time_window: int = 300):
        self.mapper = MITREAttackMapper()
        self.time_window = time_window  # 攻击链检测时间窗口（秒）
        self.session_tracker = {}  # 会话跟踪
        self.baseline_behaviors = {}  # 基线行为模式
        
    def process_nginx_logs(self, csv_file_path: str, 
                          output_file_path: str = None) -> List[EnhancedLabel]:
        """处理nginx日志并生成增强标签"""
        print(f"处理nginx日志文件: {csv_file_path}")
        
        # 读取CSV文件，使用更宽松的解析设置
        try:
            # 尝试多种解析方法
            try:
                df = pd.read_csv(csv_file_path, quoting=1, escapechar='\\')  # 严格引号模式
            except:
                try:
                    df = pd.read_csv(csv_file_path, on_bad_lines='skip')
                except:
                    # 最后手动解析
                    df = self._manual_csv_parse(csv_file_path)
            
            print(f"成功读取 {len(df)} 条记录")
        except Exception as e:
            print(f"读取CSV文件失败: {e}")
            return []
        
        # 确保必要的列存在
        required_cols = ['timestamp', 'request_method', 'request_path', 
                        'user_agent', 'payload', 'response_code']
        missing_cols = [col for col in required_cols if col not in df.columns]
        if missing_cols:
            print(f"缺少必要的列: {missing_cols}")
            return []
        
        enhanced_labels = []
        all_events = []
        
        # 处理每一行日志
        for idx, row in df.iterrows():
            try:
                # 分析单个HTTP请求
                events = self.mapper.analyze_http_request(
                    method=str(row.get('request_method', '')),
                    path=str(row.get('request_path', '')),
                    user_agent=str(row.get('user_agent', '')),
                    payload=str(row.get('payload', '')),
                    timestamp=str(row.get('timestamp', '')),
                    status_code=int(row.get('response_code', 0))
                )
                
                # 生成基本标签
                if events:
                    all_events.extend(events)
                    label = self._create_enhanced_label(row, events)
                else:
                    label = self._create_benign_label(row)
                
                enhanced_labels.append(label)
                
            except Exception as e:
                print(f"处理第 {idx} 行时出错: {e}")
                # 创建默认良性标签
                label = self._create_benign_label(row)
                enhanced_labels.append(label)
        
        # 检测攻击链并更新标签
        print("检测攻击链...")
        self._detect_and_update_chains(enhanced_labels, all_events)
        
        # 计算异常分数
        print("计算异常分数...")
        self._calculate_anomaly_scores(enhanced_labels)
        
        # 保存结果
        if output_file_path:
            self._save_enhanced_labels(enhanced_labels, output_file_path)
        
        print(f"完成处理，生成 {len(enhanced_labels)} 个增强标签")
        return enhanced_labels
    
    def _create_enhanced_label(self, row: pd.Series, 
                              events: List[AttackEvent]) -> EnhancedLabel:
        """创建攻击事件的增强标签"""
        # 生成增强标签信息
        label_info = self.mapper.generate_enhanced_labels(events)
        
        # 确定最高严重性
        severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        max_severity = max([event.severity for event in events], 
                          key=lambda x: severity_order.get(x, 0))
        
        # 确定Kill Chain阶段
        kill_chain_phase = self._map_to_kill_chain(events[0].tactic if events else None)
        
        # 确定攻击向量
        attack_vector = self._determine_attack_vector(row, events)
        
        # 行为指标
        behavioral_indicators = self._extract_behavioral_indicators(row, events)
        
        return EnhancedLabel(
            timestamp=str(row.get('timestamp', '')),
            binary_label=1,
            attack_techniques=label_info['attack_techniques'],
            attack_tactics=label_info['attack_tactics'],
            severity=max_severity,
            confidence=label_info['confidence_avg'],
            attack_chain_id=None,  # 后续更新
            chain_position=0,      # 后续更新
            chain_total_steps=0,   # 后续更新
            event_context={
                'source_ip': str(row.get('ip_src', '')),
                'target_path': str(row.get('request_path', '')),
                'http_method': str(row.get('request_method', '')),
                'status_code': int(row.get('response_code', 0)),
                'user_agent': str(row.get('user_agent', ''))
            },
            behavioral_indicators=behavioral_indicators,
            anomaly_score=0.0,     # 后续计算
            kill_chain_phase=kill_chain_phase,
            attack_vector=attack_vector,
            target_asset=self._identify_target_asset(row)
        )
    
    def _create_benign_label(self, row: pd.Series) -> EnhancedLabel:
        """创建良性事件的标签"""
        return EnhancedLabel(
            timestamp=str(row.get('timestamp', '')),
            binary_label=0,
            attack_techniques=[],
            attack_tactics=[],
            severity="NONE",
            confidence=0.0,
            attack_chain_id=None,
            chain_position=0,
            chain_total_steps=0,
            event_context={
                'source_ip': str(row.get('ip_src', '')),
                'target_path': str(row.get('request_path', '')),
                'http_method': str(row.get('request_method', '')),
                'status_code': int(row.get('response_code', 0)),
                'user_agent': str(row.get('user_agent', ''))
            },
            behavioral_indicators=self._extract_benign_indicators(row),
            anomaly_score=0.0,
            kill_chain_phase="none",
            attack_vector="none",
            target_asset=self._identify_target_asset(row)
        )
    
    def _detect_and_update_chains(self, labels: List[EnhancedLabel], 
                                 events: List[AttackEvent]):
        """检测攻击链并更新标签"""
        if not events:
            return
        
        # 使用mapper检测攻击链
        chains = self.mapper.detect_attack_chains(events, self.time_window)
        
        # 创建时间戳到标签的映射
        timestamp_to_label = {label.timestamp: label for label in labels}
        
        # 更新攻击链信息
        for chain_id, chain_events in chains.items():
            if len(chain_events) > 1:  # 只有多步骤的才算攻击链
                for idx, event in enumerate(chain_events):
                    if event.timestamp in timestamp_to_label:
                        label = timestamp_to_label[event.timestamp]
                        label.attack_chain_id = chain_id
                        label.chain_position = idx + 1
                        label.chain_total_steps = len(chain_events)
    
    def _calculate_anomaly_scores(self, labels: List[EnhancedLabel]):
        """计算异常分数"""
        # 基于多个因子计算异常分数
        for label in labels:
            score = 0.0
            
            # 基础攻击分数
            if label.binary_label == 1:
                score += 0.5
            
            # 严重性权重
            severity_weights = {"LOW": 0.1, "MEDIUM": 0.3, "HIGH": 0.5, "CRITICAL": 0.7}
            score += severity_weights.get(label.severity, 0.0)
            
            # 置信度权重
            score += label.confidence * 0.3
            
            # 攻击链权重
            if label.attack_chain_id and label.chain_total_steps > 1:
                score += 0.2 * min(label.chain_total_steps / 5, 1.0)
            
            # 行为指标权重
            score += min(len(label.behavioral_indicators) * 0.05, 0.2)
            
            # 异常状态码权重
            status_code = label.event_context.get('status_code', 200)
            if status_code >= 400:
                score += 0.1
            
            label.anomaly_score = min(score, 1.0)
    
    def _map_to_kill_chain(self, tactic: Optional[AttackPhase]) -> str:
        """映射MITRE ATT&CK战术到Kill Chain阶段"""
        if not tactic:
            return "none"
        
        kill_chain_mapping = {
            AttackPhase.RECONNAISSANCE: "reconnaissance",
            AttackPhase.RESOURCE_DEVELOPMENT: "weaponization",
            AttackPhase.INITIAL_ACCESS: "delivery",
            AttackPhase.EXECUTION: "exploitation",
            AttackPhase.PERSISTENCE: "installation",
            AttackPhase.PRIVILEGE_ESCALATION: "installation",
            AttackPhase.DEFENSE_EVASION: "installation",
            AttackPhase.CREDENTIAL_ACCESS: "command_control",
            AttackPhase.DISCOVERY: "reconnaissance",
            AttackPhase.LATERAL_MOVEMENT: "command_control",
            AttackPhase.COLLECTION: "actions_objectives",
            AttackPhase.COMMAND_AND_CONTROL: "command_control",
            AttackPhase.EXFILTRATION: "actions_objectives",
            AttackPhase.IMPACT: "actions_objectives"
        }
        
        return kill_chain_mapping.get(tactic, "unknown")
    
    def _determine_attack_vector(self, row: pd.Series, 
                               events: List[AttackEvent]) -> str:
        """确定攻击向量"""
        if not events:
            return "none"
        
        path = str(row.get('request_path', '')).lower()
        method = str(row.get('request_method', '')).upper()
        
        # 基于路径和方法判断攻击向量
        if '/api/' in path or '/rest/' in path:
            return "api_exploitation"
        elif method in ['POST', 'PUT', 'DELETE']:
            return "web_application"
        elif 'admin' in path:
            return "administrative_interface"
        else:
            return "web_application"
    
    def _identify_target_asset(self, row: pd.Series) -> str:
        """识别目标资产"""
        path = str(row.get('request_path', '')).lower()
        
        if '/admin' in path:
            return "administrative_panel"
        elif '/api/' in path or '/rest/' in path:
            return "api_service"
        elif '/user/' in path:
            return "user_service"
        elif '/product' in path:
            return "product_catalog"
        else:
            return "web_application"
    
    def _extract_behavioral_indicators(self, row: pd.Series, 
                                     events: List[AttackEvent]) -> List[str]:
        """提取行为指标"""
        indicators = []
        
        path = str(row.get('request_path', '')).lower()
        user_agent = str(row.get('user_agent', '')).lower()
        method = str(row.get('request_method', '')).upper()
        
        # 用户代理指标
        if 'attacker' in user_agent:
            indicators.append('suspicious_user_agent')
        if 'advanced-attack-tool' in user_agent:
            indicators.append('automated_attack_tool')
        
        # 路径指标
        if '../' in path or '..\\' in path:
            indicators.append('path_traversal_attempt')
        if 'admin' in path:
            indicators.append('admin_access_attempt')
        if any(keyword in path for keyword in ['config', 'backup', '.git', '.env']):
            indicators.append('sensitive_file_access')
        
        # HTTP方法指标
        if method in ['OPTIONS', 'TRACE', 'CONNECT']:
            indicators.append('http_method_enumeration')
        
        # 状态码指标
        status_code = int(row.get('response_code', 200))
        if status_code == 401:
            indicators.append('authentication_failure')
        elif status_code == 403:
            indicators.append('access_denied')
        elif status_code >= 500:
            indicators.append('server_error_triggered')
        
        return indicators
    
    def _extract_benign_indicators(self, row: pd.Series) -> List[str]:
        """提取良性行为指标"""
        indicators = []
        
        path = str(row.get('request_path', '')).lower()
        user_agent = str(row.get('user_agent', '')).lower()
        status_code = int(row.get('response_code', 200))
        
        # 良性用户代理
        if 'mozilla' in user_agent or 'chrome' in user_agent:
            indicators.append('legitimate_browser')
        
        # 良性路径
        if any(keyword in path for keyword in ['/product', '/catalog', '/home', '/about']):
            indicators.append('normal_browsing')
        
        # 成功的请求
        if status_code == 200:
            indicators.append('successful_request')
        
        return indicators
    
    def _save_enhanced_labels(self, labels: List[EnhancedLabel], 
                            output_file: str):
        """保存增强标签到文件"""
        # 转换为字典格式
        labels_data = [asdict(label) for label in labels]
        
        # 保存为JSON格式
        json_file = output_file.replace('.csv', '_enhanced_labels.json')
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(labels_data, f, indent=2, ensure_ascii=False)
        
        # 保存为CSV格式（扁平化）
        csv_file = output_file.replace('.csv', '_enhanced_labels.csv')
        flattened_data = []
        
        for label in labels:
            flat_label = {
                'timestamp': label.timestamp,
                'binary_label': label.binary_label,
                'attack_techniques': '|'.join(label.attack_techniques),
                'attack_tactics': '|'.join(label.attack_tactics),
                'severity': label.severity,
                'confidence': label.confidence,
                'attack_chain_id': label.attack_chain_id or '',
                'chain_position': label.chain_position,
                'chain_total_steps': label.chain_total_steps,
                'source_ip': label.event_context.get('source_ip', ''),
                'target_path': label.event_context.get('target_path', ''),
                'http_method': label.event_context.get('http_method', ''),
                'status_code': label.event_context.get('status_code', 0),
                'behavioral_indicators': '|'.join(label.behavioral_indicators),
                'anomaly_score': label.anomaly_score,
                'kill_chain_phase': label.kill_chain_phase,
                'attack_vector': label.attack_vector,
                'target_asset': label.target_asset
            }
            flattened_data.append(flat_label)
        
        df = pd.DataFrame(flattened_data)
        df.to_csv(csv_file, index=False)
        
        print(f"增强标签已保存:")
        print(f"  JSON格式: {json_file}")
        print(f"  CSV格式: {csv_file}")
    
    def generate_labeling_report(self, labels: List[EnhancedLabel]) -> Dict:
        """生成标签统计报告"""
        total_events = len(labels)
        attack_events = len([l for l in labels if l.binary_label == 1])
        benign_events = total_events - attack_events
        
        # 攻击技术统计
        technique_counts = {}
        for label in labels:
            for technique in label.attack_techniques:
                technique_counts[technique] = technique_counts.get(technique, 0) + 1
        
        # 攻击战术统计
        tactic_counts = {}
        for label in labels:
            for tactic in label.attack_tactics:
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        
        # 严重性分布
        severity_counts = {}
        for label in labels:
            severity_counts[label.severity] = severity_counts.get(label.severity, 0) + 1
        
        # 攻击链统计
        chain_ids = set([l.attack_chain_id for l in labels if l.attack_chain_id])
        
        report = {
            'summary': {
                'total_events': total_events,
                'attack_events': attack_events,
                'benign_events': benign_events,
                'attack_rate': attack_events / total_events if total_events > 0 else 0
            },
            'attack_techniques': dict(sorted(technique_counts.items(), 
                                           key=lambda x: x[1], reverse=True)),
            'attack_tactics': dict(sorted(tactic_counts.items(), 
                                        key=lambda x: x[1], reverse=True)),
            'severity_distribution': severity_counts,
            'attack_chains': {
                'total_chains': len(chain_ids),
                'multi_step_attacks': len([cid for cid in chain_ids if 
                                         any(l.chain_total_steps > 1 for l in labels 
                                             if l.attack_chain_id == cid)])
            },
            'anomaly_scores': {
                'mean': sum([l.anomaly_score for l in labels]) / len(labels),
                'max': max([l.anomaly_score for l in labels]),
                'high_anomaly_count': len([l for l in labels if l.anomaly_score > 0.7])
            }
        }
        
        return report
    
    def _manual_csv_parse(self, csv_file_path: str) -> pd.DataFrame:
        """手动解析有问题的CSV文件"""
        import csv
        
        print("使用手动CSV解析...")
        rows = []
        headers = None
        
        with open(csv_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # 读取第一行作为标题
            headers = f.readline().strip().split(',')
            expected_cols = len(headers)
            
            # 逐行解析
            line_num = 1
            for line in f:
                line_num += 1
                try:
                    # 简单的列分割，处理引号内的逗号
                    parts = []
                    current_part = ""
                    in_quotes = False
                    
                    for char in line:
                        if char == '"' and (not current_part or current_part[-1] != '\\'):
                            in_quotes = not in_quotes
                            current_part += char
                        elif char == ',' and not in_quotes:
                            parts.append(current_part.strip('"'))
                            current_part = ""
                        else:
                            current_part += char
                    
                    if current_part:
                        parts.append(current_part.strip('"').strip())
                    
                    # 调整列数
                    if len(parts) > expected_cols:
                        # 合并多余的列到最后一列
                        parts = parts[:expected_cols-1] + [','.join(parts[expected_cols-1:])]
                    elif len(parts) < expected_cols:
                        # 补充缺失的列
                        parts.extend([''] * (expected_cols - len(parts)))
                    
                    rows.append(parts)
                    
                except Exception as e:
                    print(f"跳过第 {line_num} 行 (解析错误): {e}")
                    continue
        
        return pd.DataFrame(rows, columns=headers)

if __name__ == "__main__":
    # 测试代码
    labeler = EnhancedGTLabeler()
    
    # 处理示例文件
    input_file = "output/test-all-features_20250827_214627/nginx_detailed.csv"
    output_file = "output/test-all-features_20250827_214627/enhanced_labels.csv"
    
    labels = labeler.process_nginx_logs(input_file, output_file)
    report = labeler.generate_labeling_report(labels)
    
    print("\n=== 标签生成报告 ===")
    print(json.dumps(report, indent=2, ensure_ascii=False))
