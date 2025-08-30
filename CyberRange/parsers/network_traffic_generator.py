#!/usr/bin/env python3
"""
网络流量标签生成器
从nginx_detailed.csv和network_traffic.pcap生成带标签的network_traffic.csv
"""

import os
import sys
import json
import logging
import pandas as pd
import re
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class NetworkTrafficGenerator:
    """网络流量CSV生成器"""
    
    def __init__(self):
        self.nginx_records = []
        self.pcap_records = []
        
    def load_nginx_csv(self, nginx_csv_path: str) -> bool:
        """加载nginx_detailed.csv"""
        try:
            # 读取CSV，处理可能的格式问题
            df = pd.read_csv(nginx_csv_path, 
                           on_bad_lines='skip',  # 跳过格式错误的行
                           quoting=1)  # 使用引号处理
            
            self.nginx_records = df.to_dict('records')
            logger.info(f"Loaded {len(self.nginx_records)} records from nginx CSV")
            return True
        except Exception as e:
            logger.error(f"Failed to load nginx CSV: {e}")
            return False
    
    def load_nginx_log(self, nginx_log_path: str) -> bool:
        """直接加载nginx detailed.log来获取完整的攻击信息"""
        try:
            records = []
            # 解析detailed日志格式（新格式）
            # Format: IP:Port - - [timestamp] "request" status size "referer" "user_agent" "attack-id" "traffic-type" "attack-type" "event-id" "chain-id" "phase" "category" "msec" "connection"
            pattern = r'^(\S+) - - \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)" "([^"]*)"'
            
            with open(nginx_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    match = re.match(pattern, line.strip())
                    if match:
                        groups = match.groups()
                        # 解析request
                        request_parts = groups[2].split()
                        method = request_parts[0] if request_parts else "UNKNOWN"
                        path = request_parts[1] if len(request_parts) > 1 else "/"
                        
                        record = {
                            'ip_src': groups[0],
                            'timestamp': groups[1],
                            'request': groups[2],
                            'status_code': groups[3],
                            'size': groups[4],
                            'referer': groups[5],
                            'user_agent': groups[6],
                            'attack_id': groups[7],  # payload_id in new format
                            'traffic_type': groups[8],
                            'attack_type': groups[9],
                            'event_id': groups[10],
                            'chain_id': groups[11],
                            'phase': groups[12],
                            'category': groups[13],
                            'msec': groups[14],
                            'connection': groups[15],
                            'method': method,
                            'path': path
                        }
                        records.append(record)
            
            self.nginx_log_records = records
            logger.info(f"Loaded {len(records)} records from nginx detailed log")
            return True
        except Exception as e:
            logger.error(f"Failed to load nginx log: {e}")
            return False
    
    def load_pcap_csv(self, pcap_csv_path: str) -> bool:
        """加载network_traffic_traffic.csv（从PCAP解析的流量数据）"""
        try:
            df = pd.read_csv(pcap_csv_path)
            self.pcap_records = df.to_dict('records')
            logger.info(f"Loaded {len(self.pcap_records)} records from PCAP CSV")
            return True
        except Exception as e:
            logger.error(f"Failed to load PCAP CSV: {e}")
            return False
    
    def generate_network_traffic_csv(self, output_path: str) -> bool:
        """生成带标签的network_traffic.csv"""
        try:
            labeled_flows = []
            
            # 优先使用nginx日志记录（如果已加载）
            records_to_use = self.nginx_log_records if hasattr(self, 'nginx_log_records') else self.nginx_records
            
            # 为每个nginx记录创建流量记录
            for nginx_record in records_to_use:
                # 提取关键信息
                timestamp = nginx_record.get('timestamp', '')
                ip_src = nginx_record.get('ip_src', '')
                request_method = nginx_record.get('method', nginx_record.get('request_method', ''))
                request_path = nginx_record.get('path', nginx_record.get('request_path', ''))
                response_code = nginx_record.get('status_code', nginx_record.get('response_code', 200))
                
                # 从nginx日志判断是否为攻击
                if 'traffic_type' in nginx_record:
                    # 使用traffic_type字段
                    is_attack = nginx_record.get('traffic_type') == 'attack'
                    payload = nginx_record.get('attack_id', '') if nginx_record.get('attack_id', '') not in ['-', ''] else ''
                    attack_type = nginx_record.get('attack_type', '')
                    chain_id = nginx_record.get('chain_id', '')
                    phase = nginx_record.get('phase', '')
                    event_id = nginx_record.get('event_id', '')
                else:
                    # 从CSV记录
                    label = nginx_record.get('label', 0)
                    is_attack = label == 1 or label == '1'
                    payload = nginx_record.get('payload', '')
                    attack_type = ''
                    chain_id = ''
                    phase = ''
                    event_id = ''
                
                # 生成事件阶段标签
                if 'traffic_type' in nginx_record:
                    # 直接使用nginx日志中的信息
                    event_stage_label = self._generate_event_stage_label_from_log(
                        is_attack, payload, chain_id, phase, attack_type, event_id
                    )
                else:
                    event_stage_label = self._generate_event_stage_label(
                        is_attack, payload, nginx_record
                    )
                
                # 创建流量记录
                flow_record = {
                    'timestamp': timestamp,
                    'src_ip': ip_src,
                    'dst_ip': '172.18.0.2',  # nginx容器IP（假设）
                    'src_port': 0,  # 从旧格式日志无法获取
                    'dst_port': 80,
                    'protocol': 'TCP',
                    'packets': 1,
                    'bytes': int(nginx_record.get('size', 0)) if 'size' in nginx_record else 1000,
                    'duration': 0.1,  # 默认持续时间
                    'http_method': request_method,
                    'http_path': request_path,
                    'http_status': response_code,
                    'binary_label': 1 if is_attack else 0,
                    'event_stage_label': event_stage_label,
                    'attack_type': self._extract_attack_type(attack_type if 'traffic_type' in nginx_record else payload) if is_attack else '',
                    'confidence': 'high'  # 基于nginx日志的标签置信度高
                }
                
                labeled_flows.append(flow_record)
            
            # 创建DataFrame并保存
            df = pd.DataFrame(labeled_flows)
            
            # 添加统计信息列
            df['flow_id'] = range(1, len(df) + 1)
            
            # 保存CSV
            df.to_csv(output_path, index=False)
            
            # 生成统计信息
            stats = {
                'total_flows': len(df),
                'attack_flows': len(df[df['binary_label'] == 1]),
                'benign_flows': len(df[df['binary_label'] == 0]),
                'unique_attack_types': df[df['binary_label'] == 1]['attack_type'].nunique(),
                'attack_distribution': df[df['binary_label'] == 1]['attack_type'].value_counts().to_dict()
            }
            
            logger.info(f"Generated network traffic CSV: {output_path}")
            logger.info(f"Statistics: {json.dumps(stats, indent=2)}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate network traffic CSV: {e}")
            return False
    
    def _generate_event_stage_label(self, is_attack: bool, payload: str, record: Dict) -> str:
        """生成事件阶段标签"""
        if not is_attack:
            return 'benign'
        
        # 从payload提取信息
        if not payload or payload == '-':
            return 'unknown_attack'
        
        # 检查是否有chain_id和phase信息（新字段）
        chain_id = record.get('chain_id', '')
        phase = record.get('phase', '')
        
        if chain_id and chain_id != '-':
            # 高级攻击
            if phase and phase != '-':
                return f"{chain_id}_phase{phase}"
            else:
                return chain_id
        
        # 基础攻击 - 使用payload作为标识
        if payload.startswith('basic_'):
            return payload
        elif '_' in payload:
            # 尝试解析攻击类型和ID
            parts = payload.split('_')
            if len(parts) >= 2:
                return f"basic_{parts[0]}_{parts[1]}"
        
        return f"attack_{payload}"
    
    def _generate_event_stage_label_from_log(self, is_attack: bool, payload: str, 
                                            chain_id: str, phase: str, attack_type: str, 
                                            event_id: str = '') -> str:
        """从nginx日志信息生成事件阶段标签"""
        if not is_attack:
            return 'benign'
        
        # 使用chain_id作为主要标识
        if chain_id and chain_id != '-':
            # 对于高级攻击，包含phase信息
            if chain_id.startswith('advanced_'):
                if phase and phase != '-':
                    return f"{chain_id}_phase{phase}"
                else:
                    return chain_id
            # 对于基础攻击
            else:
                return chain_id
        
        # 如果没有chain_id，使用payload
        if payload and payload != '-':
            return payload
        
        # 最后使用attack_type
        if attack_type and attack_type != '-':
            return f"attack_{attack_type}"
        
        return 'unknown_attack'
    
    def _extract_attack_type(self, payload: str) -> str:
        """从payload提取攻击类型"""
        if not payload or payload == '-':
            return 'unknown'
        
        # 常见攻击类型映射
        attack_types = {
            'sql': 'SQL Injection',
            'xss': 'Cross-Site Scripting',
            'cmd': 'Command Injection',
            'file': 'File Access',
            'path': 'Path Traversal',
            'auth': 'Authentication Attack',
            'method': 'HTTP Method Attack',
            'api': 'API Attack'
        }
        
        # 尝试从payload提取攻击类型
        payload_lower = payload.lower()
        for key, name in attack_types.items():
            if key in payload_lower:
                return name
        
        # 如果payload以攻击类型开头
        parts = payload.split('_')
        if parts[0] in attack_types:
            return attack_types[parts[0]]
        
        return 'Other'


def process_network_traffic(nginx_csv_path: str, pcap_csv_path: str, output_dir: str) -> bool:
    """处理网络流量数据的主函数"""
    try:
        generator = NetworkTrafficGenerator()
        
        # 尝试先加载nginx详细日志（如果存在）
        nginx_log_path = nginx_csv_path.replace('/output/', '/logs/').replace('_detailed.csv', '/detailed.log')
        if os.path.exists(nginx_log_path):
            logger.info(f"Loading nginx detailed log: {nginx_log_path}")
            generator.load_nginx_log(nginx_log_path)
        else:
            # 否则加载CSV
            if not generator.load_nginx_csv(nginx_csv_path):
                return False
        
        # 如果有PCAP CSV，也加载（可选）
        if os.path.exists(pcap_csv_path):
            generator.load_pcap_csv(pcap_csv_path)
        
        # 生成network_traffic.csv
        output_path = os.path.join(output_dir, 'network_traffic.csv')
        return generator.generate_network_traffic_csv(output_path)
        
    except Exception as e:
        logger.error(f"Failed to process network traffic: {e}")
        return False


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python network_traffic_generator.py <nginx_csv> <pcap_csv> <output_dir>")
        sys.exit(1)
    
    nginx_csv = sys.argv[1]
    pcap_csv = sys.argv[2]
    output_dir = sys.argv[3]
    
    if not os.path.exists(nginx_csv):
        print(f"Error: Nginx CSV not found: {nginx_csv}")
        sys.exit(1)
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    success = process_network_traffic(nginx_csv, pcap_csv, output_dir)
    sys.exit(0 if success else 1)
