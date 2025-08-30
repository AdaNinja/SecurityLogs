#!/usr/bin/env python3
"""
Network Traffic Summary Generator
生成网络流量CSV的详细分析报告
"""

import pandas as pd
import json
import os
import sys
from collections import Counter, defaultdict
import logging

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TrafficSummaryGenerator:
    def __init__(self):
        self.summary_data = {}
        
    def analyze_network_traffic(self, csv_path):
        """分析网络流量CSV文件"""
        try:
            # 读取CSV文件
            df = pd.read_csv(csv_path)
            logger.info(f"Loaded {len(df)} records from {csv_path}")
            
            # 基本统计
            total_flows = len(df)
            attack_flows = df[df['binary_label'] == 1]
            benign_flows = df[df['binary_label'] == 0]
            
            # 攻击类型统计
            attack_types = attack_flows['attack_type'].value_counts().to_dict()
            
            # 事件阶段标签统计
            event_stage_labels = df['event_stage_label'].value_counts().to_dict()
            
            # IP地址统计
            src_ips = df['src_ip'].value_counts().to_dict()
            
            # HTTP方法统计
            http_methods = df['http_method'].value_counts().to_dict()
            
            # HTTP状态码统计
            http_status = df['http_status'].value_counts().to_dict()
            
            # 攻击链分析
            attack_chains = self._analyze_attack_chains(attack_flows)
            
            # 时间分析
            time_analysis = self._analyze_time_patterns(df)
            
            # 构建summary
            self.summary_data = {
                "basic_statistics": {
                    "total_flows": int(total_flows),
                    "attack_flows": int(len(attack_flows)),
                    "benign_flows": int(len(benign_flows)),
                    "attack_percentage": round((len(attack_flows) / total_flows) * 100, 2),
                    "benign_percentage": round((len(benign_flows) / total_flows) * 100, 2)
                },
                "attack_analysis": {
                    "attack_types": {k: int(v) for k, v in attack_types.items()},
                    "unique_attack_types": len(attack_types),
                    "attack_chains": attack_chains
                },
                "event_stage_analysis": {
                    "event_stage_labels": {k: int(v) for k, v in event_stage_labels.items()},
                    "unique_event_stages": len(event_stage_labels)
                },
                "network_analysis": {
                    "source_ips": {k: int(v) for k, v in src_ips.items()},
                    "unique_source_ips": len(src_ips),
                    "http_methods": {k: int(v) for k, v in http_methods.items()},
                    "http_status_codes": {str(k): int(v) for k, v in http_status.items()}
                },
                "time_analysis": time_analysis
            }
            
            return True
            
        except Exception as e:
            logger.error(f"Error analyzing network traffic: {e}")
            return False
    
    def _analyze_attack_chains(self, attack_flows):
        """分析攻击链"""
        if attack_flows.empty:
            return {}
            
        # 提取攻击链信息
        chain_info = defaultdict(lambda: {
            "total_requests": 0,
            "attack_types": set(),
            "phases": set(),
            "event_ids": set()
        })
        
        for _, row in attack_flows.iterrows():
            event_stage = row['event_stage_label']
            if pd.isna(event_stage) or event_stage == 'benign':
                continue
                
            # 解析攻击链ID
            if '_chain_' in event_stage:
                chain_id = event_stage
            elif event_stage.startswith('basic_'):
                chain_id = f"basic_attack_{row['attack_type']}"
            else:
                chain_id = event_stage
                
            chain_info[chain_id]["total_requests"] += 1
            chain_info[chain_id]["attack_types"].add(row['attack_type'])
            
            # 尝试提取阶段信息
            if 'phase' in str(row.get('http_path', '')):
                try:
                    phase = str(row['http_path']).split('phase')[1][0]
                    chain_info[chain_id]["phases"].add(phase)
                except:
                    pass
        
        # 转换为可序列化的格式
        result = {}
        for chain_id, info in chain_info.items():
            result[chain_id] = {
                "total_requests": info["total_requests"],
                "attack_types": list(info["attack_types"]),
                "unique_attack_types": len(info["attack_types"]),
                "phases": sorted(list(info["phases"])) if info["phases"] else [],
                "phase_count": len(info["phases"])
            }
        
        return result
    
    def _analyze_time_patterns(self, df):
        """分析时间模式"""
        try:
            # 转换时间戳
            df['timestamp_parsed'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')
            
            if df['timestamp_parsed'].isna().all():
                return {"error": "Unable to parse timestamps"}
            
            # 按分钟统计
            df['minute'] = df['timestamp_parsed'].dt.floor('min')
            minute_stats = df.groupby('minute').agg({
                'binary_label': ['count', 'sum']
            }).round(2)
            
            minute_stats.columns = ['total_requests', 'attack_requests']
            minute_stats['benign_requests'] = minute_stats['total_requests'] - minute_stats['attack_requests']
            
            # 转换为字典格式
            time_analysis = {
                "duration_minutes": len(minute_stats),
                "start_time": str(df['timestamp_parsed'].min()),
                "end_time": str(df['timestamp_parsed'].max()),
                "minute_by_minute": minute_stats.to_dict('index')
            }
            
            # 转换时间索引为字符串
            time_analysis["minute_by_minute"] = {
                str(k): v for k, v in time_analysis["minute_by_minute"].items()
            }
            
            return time_analysis
            
        except Exception as e:
            logger.warning(f"Time analysis failed: {e}")
            return {"error": str(e)}
    
    def generate_summary_report(self, output_path):
        """生成summary报告"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.summary_data, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"Summary report generated: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error generating summary report: {e}")
            return False
    
    def print_summary(self):
        """打印summary到控制台"""
        print("\n" + "="*60)
        print("🔍 NETWORK TRAFFIC ANALYSIS SUMMARY")
        print("="*60)
        
        basic = self.summary_data.get('basic_statistics', {})
        print(f"📊 Basic Statistics:")
        print(f"   Total Flows: {basic.get('total_flows', 0)}")
        print(f"   Attack Flows: {basic.get('attack_flows', 0)} ({basic.get('attack_percentage', 0)}%)")
        print(f"   Benign Flows: {basic.get('benign_flows', 0)} ({basic.get('benign_percentage', 0)}%)")
        
        attack = self.summary_data.get('attack_analysis', {})
        print(f"\n🎯 Attack Analysis:")
        print(f"   Unique Attack Types: {attack.get('unique_attack_types', 0)}")
        attack_types = attack.get('attack_types', {})
        for attack_type, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
            if attack_type and attack_type != '':
                print(f"   - {attack_type}: {count}")
        
        chains = attack.get('attack_chains', {})
        if chains:
            print(f"\n🔗 Attack Chains: {len(chains)} chains detected")
            for chain_id, info in list(chains.items())[:5]:  # 显示前5个
                print(f"   - {chain_id}: {info.get('total_requests', 0)} requests")
        
        network = self.summary_data.get('network_analysis', {})
        print(f"\n🌐 Network Analysis:")
        print(f"   Unique Source IPs: {network.get('unique_source_ips', 0)}")
        
        src_ips = network.get('source_ips', {})
        print("   Top Source IPs:")
        for ip, count in sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"   - {ip}: {count} requests")
        
        print("\n" + "="*60)

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 traffic_summary_generator.py <input_csv> <output_json>")
        sys.exit(1)
    
    input_csv = sys.argv[1]
    output_json = sys.argv[2]
    
    if not os.path.exists(input_csv):
        logger.error(f"Input file not found: {input_csv}")
        sys.exit(1)
    
    generator = TrafficSummaryGenerator()
    
    if generator.analyze_network_traffic(input_csv):
        generator.print_summary()
        
        if generator.generate_summary_report(output_json):
            logger.info("✅ Traffic summary generation completed successfully")
        else:
            logger.error("❌ Failed to generate summary report")
            sys.exit(1)
    else:
        logger.error("❌ Failed to analyze network traffic")
        sys.exit(1)

if __name__ == "__main__":
    main()
