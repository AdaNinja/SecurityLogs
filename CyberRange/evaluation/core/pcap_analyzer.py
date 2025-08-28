#!/usr/bin/env python3
"""
PCAP Analyzer
PCAP文件分析器，提取流量特征和统计信息
"""

import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import pandas as pd
import numpy as np
from datetime import datetime
from collections import defaultdict, Counter
import pyshark
import subprocess
import json


class PCAPAnalyzer:
    """PCAP文件分析器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # 定义常见端口
        self.common_ports = {
            80: 'HTTP',
            443: 'HTTPS', 
            8080: 'HTTP-ALT',
            3000: 'APP',
            22: 'SSH',
            21: 'FTP',
            25: 'SMTP',
            3306: 'MySQL',
            5432: 'PostgreSQL'
        }
    
    def analyze_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """
        分析PCAP文件，提取全面的流量特征
        
        Args:
            pcap_path: PCAP文件路径
            
        Returns:
            包含流量特征的字典
        """
        self.logger.info(f"Analyzing PCAP: {pcap_path}")
        
        pcap_file = Path(pcap_path)
        if not pcap_file.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        
        analysis_result = {
            'file_info': self._get_file_info(pcap_file),
            'basic_stats': {},
            'protocol_distribution': {},
            'flow_statistics': {},
            'http_analysis': {},
            'temporal_analysis': {},
            'anomaly_indicators': {}
        }
        
        try:
            # 基础统计信息
            analysis_result['basic_stats'] = self._get_basic_stats(pcap_path)
            
            # 协议分布
            analysis_result['protocol_distribution'] = self._analyze_protocols(pcap_path)
            
            # 流量统计
            analysis_result['flow_statistics'] = self._analyze_flows(pcap_path)
            
            # HTTP分析
            analysis_result['http_analysis'] = self._analyze_http_traffic(pcap_path)
            
            # 时间分析
            analysis_result['temporal_analysis'] = self._analyze_temporal_patterns(pcap_path)
            
            # 异常指标
            analysis_result['anomaly_indicators'] = self._detect_anomalies(analysis_result)
            
        except Exception as e:
            self.logger.error(f"Error analyzing PCAP: {e}")
            analysis_result['error'] = str(e)
        
        return analysis_result
    
    def _get_file_info(self, pcap_file: Path) -> Dict:
        """获取文件基本信息"""
        return {
            'filename': pcap_file.name,
            'size_mb': pcap_file.stat().st_size / (1024 * 1024),
            'modified': datetime.fromtimestamp(pcap_file.stat().st_mtime).isoformat()
        }
    
    def _get_basic_stats(self, pcap_path: str) -> Dict:
        """获取基础统计信息"""
        stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'duration': 0,
            'avg_packet_size': 0,
            'packets_per_second': 0
        }
        
        try:
            # 使用capinfos获取基础信息
            result = subprocess.run(
                ['capinfos', '-T', '-m', pcap_path],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\t')
                if len(lines) >= 7:
                    stats['total_packets'] = int(lines[4])
                    stats['total_bytes'] = int(lines[5])
                    stats['duration'] = float(lines[6])
                    
                    if stats['total_packets'] > 0:
                        stats['avg_packet_size'] = stats['total_bytes'] / stats['total_packets']
                    if stats['duration'] > 0:
                        stats['packets_per_second'] = stats['total_packets'] / stats['duration']
            
        except Exception as e:
            self.logger.warning(f"capinfos failed, using pyshark: {e}")
            # 使用pyshark作为备选方案
            stats = self._get_basic_stats_pyshark(pcap_path)
        
        return stats
    
    def _get_basic_stats_pyshark(self, pcap_path: str) -> Dict:
        """使用pyshark获取基础统计"""
        stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'duration': 0,
            'avg_packet_size': 0,
            'packets_per_second': 0
        }
        
        cap = pyshark.FileCapture(pcap_path, only_summaries=True)
        
        first_time = None
        last_time = None
        
        for packet in cap:
            stats['total_packets'] += 1
            if hasattr(packet, 'length'):
                stats['total_bytes'] += int(packet.length)
            
            if hasattr(packet, 'time'):
                packet_time = float(packet.time)
                if first_time is None:
                    first_time = packet_time
                last_time = packet_time
        
        cap.close()
        
        if first_time and last_time:
            stats['duration'] = last_time - first_time
        
        if stats['total_packets'] > 0:
            stats['avg_packet_size'] = stats['total_bytes'] / stats['total_packets']
        if stats['duration'] > 0:
            stats['packets_per_second'] = stats['total_packets'] / stats['duration']
        
        return stats
    
    def _analyze_protocols(self, pcap_path: str) -> Dict:
        """分析协议分布"""
        protocol_count = defaultdict(int)
        port_count = defaultdict(int)
        
        try:
            cap = pyshark.FileCapture(
                pcap_path, 
                display_filter='tcp or udp',
                only_summaries=False
            )
            
            packet_count = 0
            for packet in cap:
                packet_count += 1
                if packet_count > 10000:  # 限制分析数量避免内存溢出
                    break
                
                # 协议统计
                if hasattr(packet, 'highest_layer'):
                    protocol_count[packet.highest_layer] += 1
                
                # 端口统计
                if hasattr(packet, 'tcp'):
                    if hasattr(packet.tcp, 'dstport'):
                        port_count[int(packet.tcp.dstport)] += 1
                elif hasattr(packet, 'udp'):
                    if hasattr(packet.udp, 'dstport'):
                        port_count[int(packet.udp.dstport)] += 1
            
            cap.close()
            
        except Exception as e:
            self.logger.error(f"Protocol analysis error: {e}")
        
        # 获取top协议和端口
        top_protocols = dict(Counter(protocol_count).most_common(10))
        top_ports = dict(Counter(port_count).most_common(10))
        
        # 映射端口到服务名
        port_services = {}
        for port, count in top_ports.items():
            service = self.common_ports.get(port, f'port_{port}')
            port_services[service] = count
        
        return {
            'protocols': top_protocols,
            'ports': top_ports,
            'services': port_services
        }
    
    def _analyze_flows(self, pcap_path: str) -> Dict:
        """分析流量模式"""
        flows = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        ip_stats = defaultdict(lambda: {'sent': 0, 'received': 0})
        
        try:
            cap = pyshark.FileCapture(
                pcap_path,
                display_filter='ip',
                only_summaries=False
            )
            
            packet_count = 0
            for packet in cap:
                packet_count += 1
                if packet_count > 10000:
                    break
                
                if hasattr(packet, 'ip'):
                    # 流统计
                    src = packet.ip.src
                    dst = packet.ip.dst
                    flow_key = f"{src}->{dst}"
                    
                    flows[flow_key]['packets'] += 1
                    if hasattr(packet, 'length'):
                        flows[flow_key]['bytes'] += int(packet.length)
                    
                    # IP统计
                    ip_stats[src]['sent'] += 1
                    ip_stats[dst]['received'] += 1
            
            cap.close()
            
        except Exception as e:
            self.logger.error(f"Flow analysis error: {e}")
        
        # 计算流量特征
        flow_counts = [f['packets'] for f in flows.values()]
        flow_sizes = [f['bytes'] for f in flows.values()]
        
        flow_statistics = {
            'total_flows': len(flows),
            'avg_packets_per_flow': np.mean(flow_counts) if flow_counts else 0,
            'max_packets_per_flow': max(flow_counts) if flow_counts else 0,
            'avg_bytes_per_flow': np.mean(flow_sizes) if flow_sizes else 0,
            'unique_ips': len(ip_stats),
            'top_talkers': self._get_top_talkers(ip_stats)
        }
        
        return flow_statistics
    
    def _get_top_talkers(self, ip_stats: Dict, top_n: int = 5) -> List[Dict]:
        """获取流量最大的IP"""
        talkers = []
        
        for ip, stats in ip_stats.items():
            total_packets = stats['sent'] + stats['received']
            talkers.append({
                'ip': ip,
                'total_packets': total_packets,
                'sent': stats['sent'],
                'received': stats['received']
            })
        
        # 按总流量排序
        talkers.sort(key=lambda x: x['total_packets'], reverse=True)
        
        return talkers[:top_n]
    
    def _analyze_http_traffic(self, pcap_path: str) -> Dict:
        """分析HTTP流量"""
        http_stats = {
            'total_requests': 0,
            'methods': defaultdict(int),
            'status_codes': defaultdict(int),
            'user_agents': defaultdict(int),
            'suspicious_requests': []
        }
        
        # 可疑模式
        suspicious_patterns = [
            'union select', '<script', '../..', 'exec(',
            'cmd=', '/etc/passwd', 'document.cookie'
        ]
        
        try:
            cap = pyshark.FileCapture(
                pcap_path,
                display_filter='http',
                only_summaries=False
            )
            
            for packet in cap:
                if hasattr(packet, 'http'):
                    # HTTP请求
                    if hasattr(packet.http, 'request_method'):
                        http_stats['total_requests'] += 1
                        http_stats['methods'][packet.http.request_method] += 1
                        
                        # 检查可疑请求
                        if hasattr(packet.http, 'request_uri'):
                            uri = packet.http.request_uri
                            for pattern in suspicious_patterns:
                                if pattern in uri.lower():
                                    http_stats['suspicious_requests'].append({
                                        'uri': uri,
                                        'method': packet.http.request_method,
                                        'pattern': pattern
                                    })
                                    break
                    
                    # HTTP响应
                    if hasattr(packet.http, 'response_code'):
                        http_stats['status_codes'][packet.http.response_code] += 1
                    
                    # User-Agent
                    if hasattr(packet.http, 'user_agent'):
                        ua = packet.http.user_agent[:50]  # 截断避免过长
                        http_stats['user_agents'][ua] += 1
            
            cap.close()
            
        except Exception as e:
            self.logger.error(f"HTTP analysis error: {e}")
        
        # 转换为普通字典并限制数量
        http_stats['methods'] = dict(http_stats['methods'])
        http_stats['status_codes'] = dict(http_stats['status_codes'])
        http_stats['user_agents'] = dict(Counter(http_stats['user_agents']).most_common(5))
        http_stats['suspicious_requests'] = http_stats['suspicious_requests'][:10]
        
        return http_stats
    
    def _analyze_temporal_patterns(self, pcap_path: str) -> Dict:
        """分析时间模式"""
        timestamps = []
        max_packets = getattr(self, 'max_packets', 5000)  # 使用配置的限制
        
        try:
            cap = pyshark.FileCapture(pcap_path, only_summaries=True)
            
            packet_count = 0
            for packet in cap:
                if hasattr(packet, 'time'):
                    timestamps.append(float(packet.time))
                
                packet_count += 1
                if packet_count >= max_packets:  # 应用max_packets限制
                    break
            
            cap.close()
            
        except Exception as e:
            self.logger.error(f"Temporal analysis error: {e}")
        
        if not timestamps:
            return {}
        
        # 计算时间间隔
        timestamps.sort()
        intervals = np.diff(timestamps)
        
        # 计算包速率（每秒）
        duration = timestamps[-1] - timestamps[0]
        time_bins = int(duration) + 1
        packet_rates = []
        
        if time_bins > 0 and time_bins < 3600:  # 限制最多1小时
            counts, _ = np.histogram(timestamps, bins=time_bins)
            packet_rates = counts.tolist()
        
        temporal_stats = {
            'duration_seconds': duration,
            'avg_packet_interval': np.mean(intervals) if len(intervals) > 0 else 0,
            'min_packet_interval': np.min(intervals) if len(intervals) > 0 else 0,
            'max_packet_interval': np.max(intervals) if len(intervals) > 0 else 0,
            'packet_rate_variance': np.var(packet_rates) if packet_rates else 0,
            'burst_periods': self._detect_bursts(packet_rates) if packet_rates else 0
        }
        
        return temporal_stats
    
    def _detect_bursts(self, packet_rates: List[int], threshold_factor: float = 2.0) -> int:
        """检测突发流量时段"""
        if not packet_rates:
            return 0
        
        mean_rate = np.mean(packet_rates)
        threshold = mean_rate * threshold_factor
        
        burst_count = sum(1 for rate in packet_rates if rate > threshold)
        
        return burst_count
    
    def _detect_anomalies(self, analysis_result: Dict) -> Dict:
        """基于分析结果检测异常指标"""
        anomalies = {
            'high_packet_rate': False,
            'suspicious_http_activity': False,
            'port_scan_activity': False,
            'traffic_burst': False,
            'unusual_protocols': False
        }
        
        # 检测高包速率（>1000 pps可能是DDoS）
        if 'basic_stats' in analysis_result:
            pps = analysis_result['basic_stats'].get('packets_per_second', 0)
            anomalies['high_packet_rate'] = pps > 1000
        
        # 检测可疑HTTP活动
        if 'http_analysis' in analysis_result:
            suspicious_count = len(analysis_result['http_analysis'].get('suspicious_requests', []))
            anomalies['suspicious_http_activity'] = suspicious_count > 0
        
        # 检测端口扫描（多个端口少量流量）
        if 'protocol_distribution' in analysis_result:
            ports = analysis_result['protocol_distribution'].get('ports', {})
            if len(ports) > 20:  # 访问超过20个不同端口
                anomalies['port_scan_activity'] = True
        
        # 检测流量突发
        if 'temporal_analysis' in analysis_result:
            burst_periods = analysis_result['temporal_analysis'].get('burst_periods', 0)
            anomalies['traffic_burst'] = burst_periods > 5
        
        # 计算异常分数
        anomaly_count = sum(anomalies.values())
        anomalies['anomaly_score'] = anomaly_count / len(anomalies)
        
        return anomalies
    
    def compare_pcaps(self, pcap1_path: str, pcap2_path: str) -> Dict:
        """
        比较两个PCAP文件的特征
        
        Returns:
            比较结果字典
        """
        self.logger.info(f"Comparing PCAPs: {pcap1_path} vs {pcap2_path}")
        
        # 分析两个PCAP
        analysis1 = self.analyze_pcap(pcap1_path)
        analysis2 = self.analyze_pcap(pcap2_path)
        
        comparison = {
            'file1': Path(pcap1_path).name,
            'file2': Path(pcap2_path).name,
            'size_ratio': analysis1['file_info']['size_mb'] / analysis2['file_info']['size_mb'],
            'packet_ratio': (analysis1['basic_stats']['total_packets'] / 
                           analysis2['basic_stats']['total_packets']),
            'similarity_scores': {}
        }
        
        # 计算各维度相似度
        # 1. 协议分布相似度
        if 'protocol_distribution' in analysis1 and 'protocol_distribution' in analysis2:
            proto_sim = self._calculate_distribution_similarity(
                analysis1['protocol_distribution']['protocols'],
                analysis2['protocol_distribution']['protocols']
            )
            comparison['similarity_scores']['protocol'] = proto_sim
        
        # 2. 端口分布相似度
        if 'protocol_distribution' in analysis1 and 'protocol_distribution' in analysis2:
            port_sim = self._calculate_distribution_similarity(
                analysis1['protocol_distribution']['ports'],
                analysis2['protocol_distribution']['ports']
            )
            comparison['similarity_scores']['port'] = port_sim
        
        # 3. HTTP特征相似度
        if 'http_analysis' in analysis1 and 'http_analysis' in analysis2:
            http_sim = self._calculate_http_similarity(
                analysis1['http_analysis'],
                analysis2['http_analysis']
            )
            comparison['similarity_scores']['http'] = http_sim
        
        # 计算总体相似度
        if comparison['similarity_scores']:
            comparison['overall_similarity'] = np.mean(list(comparison['similarity_scores'].values()))
        else:
            comparison['overall_similarity'] = 0
        
        return comparison
    
    def _calculate_distribution_similarity(self, dist1: Dict, dist2: Dict) -> float:
        """计算两个分布的相似度（使用Jaccard系数）"""
        if not dist1 or not dist2:
            return 0
        
        keys1 = set(dist1.keys())
        keys2 = set(dist2.keys())
        
        intersection = keys1.intersection(keys2)
        union = keys1.union(keys2)
        
        if not union:
            return 0
        
        # Jaccard相似度
        jaccard = len(intersection) / len(union)
        
        # 考虑数值分布的相似度
        if intersection:
            value_sim = []
            for key in intersection:
                v1 = dist1[key]
                v2 = dist2[key]
                # 使用相对差异
                sim = 1 - abs(v1 - v2) / (v1 + v2) if (v1 + v2) > 0 else 1
                value_sim.append(sim)
            
            value_similarity = np.mean(value_sim)
            # 结合Jaccard和数值相似度
            return (jaccard + value_similarity) / 2
        
        return jaccard
    
    def _calculate_http_similarity(self, http1: Dict, http2: Dict) -> float:
        """计算HTTP特征相似度"""
        similarities = []
        
        # 方法分布相似度
        if 'methods' in http1 and 'methods' in http2:
            method_sim = self._calculate_distribution_similarity(
                http1['methods'], 
                http2['methods']
            )
            similarities.append(method_sim)
        
        # 状态码分布相似度
        if 'status_codes' in http1 and 'status_codes' in http2:
            status_sim = self._calculate_distribution_similarity(
                http1['status_codes'],
                http2['status_codes']
            )
            similarities.append(status_sim)
        
        # 可疑请求相似度
        susp1 = len(http1.get('suspicious_requests', []))
        susp2 = len(http2.get('suspicious_requests', []))
        if susp1 > 0 or susp2 > 0:
            susp_sim = 1 - abs(susp1 - susp2) / (susp1 + susp2)
            similarities.append(susp_sim)
        
        return np.mean(similarities) if similarities else 0


def main():
    """测试PCAP分析器"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze PCAP files")
    parser.add_argument("pcap", help="PCAP file to analyze")
    parser.add_argument("--compare", help="Second PCAP file for comparison")
    parser.add_argument("--output", help="Output JSON file for results")
    
    args = parser.parse_args()
    
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 创建分析器
    analyzer = PCAPAnalyzer()
    
    # 分析PCAP
    print(f"\n📊 Analyzing PCAP: {args.pcap}")
    analysis = analyzer.analyze_pcap(args.pcap)
    
    # 打印摘要
    print(f"\n📈 Analysis Summary:")
    print(f"  Total packets: {analysis['basic_stats']['total_packets']:,}")
    print(f"  Duration: {analysis['basic_stats']['duration']:.2f} seconds")
    print(f"  Packet rate: {analysis['basic_stats']['packets_per_second']:.2f} pps")
    
    if 'anomaly_indicators' in analysis:
        print(f"\n🚨 Anomaly Score: {analysis['anomaly_indicators']['anomaly_score']:.2f}")
    
    # 比较分析
    if args.compare:
        print(f"\n🔄 Comparing with: {args.compare}")
        comparison = analyzer.compare_pcaps(args.pcap, args.compare)
        print(f"  Overall similarity: {comparison['overall_similarity']:.2%}")
    
    # 保存结果
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(analysis, f, indent=2, default=str)
        print(f"\n✅ Results saved to: {args.output}")
    
    return 0


if __name__ == "__main__":
    exit(main())
