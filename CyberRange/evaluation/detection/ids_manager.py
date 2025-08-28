#!/usr/bin/env python3
"""
IDS Manager
管理和协调多个IDS工具的检测任务
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
import json
import pandas as pd
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from .suricata_detector import SuricataDetector


class IDSManager:
    """IDS管理器"""
    
    def __init__(self, output_dir: str = "./ids_results"):
        """
        初始化IDS管理器
        
        Args:
            output_dir: IDS检测结果输出目录
        """
        self.logger = logging.getLogger(__name__)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 初始化支持的IDS检测器
        self.detectors = {
            'suricata': SuricataDetector(str(self.output_dir / 'suricata'))
        }
        
        # 未来可以添加更多检测器
        # self.detectors['snort'] = SnortDetector(str(self.output_dir / 'snort'))
        # self.detectors['zeek'] = ZeekDetector(str(self.output_dir / 'zeek'))
        
        self.logger.info(f"IDS Manager initialized with {len(self.detectors)} detectors")
    
    def detect_single(self, detector_name: str, pcap_path: str, 
                     label: str = "unknown") -> Dict:
        """
        使用单个IDS检测PCAP
        
        Args:
            detector_name: IDS名称
            pcap_path: PCAP文件路径
            label: 数据集标签
            
        Returns:
            检测结果
        """
        if detector_name not in self.detectors:
            raise ValueError(f"Unknown detector: {detector_name}")
        
        detector = self.detectors[detector_name]
        
        self.logger.info(f"Running {detector_name} on {pcap_path}")
        
        try:
            result = detector.detect(pcap_path, label)
            return {
                'detector': detector_name,
                'pcap': pcap_path,
                'label': label,
                'success': True,
                'result': result,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"{detector_name} detection failed: {e}")
            return {
                'detector': detector_name,
                'pcap': pcap_path,
                'label': label,
                'success': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def detect_multiple(self, pcap_path: str, detectors: List[str] = None,
                       label: str = "unknown", parallel: bool = True) -> Dict:
        """
        使用多个IDS检测同一个PCAP
        
        Args:
            pcap_path: PCAP文件路径
            detectors: 要使用的检测器列表，None表示使用所有
            label: 数据集标签
            parallel: 是否并行执行
            
        Returns:
            所有检测器的结果
        """
        if detectors is None:
            detectors = list(self.detectors.keys())
        
        results = {
            'pcap': pcap_path,
            'label': label,
            'detections': {},
            'summary': {}
        }
        
        if parallel and len(detectors) > 1:
            # 并行执行
            with ThreadPoolExecutor(max_workers=len(detectors)) as executor:
                future_to_detector = {
                    executor.submit(self.detect_single, detector, pcap_path, label): detector
                    for detector in detectors
                }
                
                for future in as_completed(future_to_detector):
                    detector = future_to_detector[future]
                    try:
                        result = future.result()
                        results['detections'][detector] = result
                    except Exception as e:
                        self.logger.error(f"Error in parallel detection for {detector}: {e}")
                        results['detections'][detector] = {
                            'success': False,
                            'error': str(e)
                        }
        else:
            # 串行执行
            for detector in detectors:
                results['detections'][detector] = self.detect_single(detector, pcap_path, label)
        
        # 生成摘要
        results['summary'] = self._generate_detection_summary(results['detections'])
        
        return results
    
    def detect_dataset_pair(self, cyberrange_pcap: str, baseline_pcaps: Dict[str, str],
                          detectors: List[str] = None) -> Dict:
        """
        检测CyberRange和基准数据集对
        
        Args:
            cyberrange_pcap: CyberRange PCAP路径
            baseline_pcaps: 基准PCAP路径字典
            detectors: 要使用的检测器列表
            
        Returns:
            成对的检测结果
        """
        self.logger.info("Detecting dataset pairs")
        
        results = {
            'cyberrange': {},
            'baseline': {},
            'comparison': {}
        }
        
        # 检测CyberRange数据集
        results['cyberrange'] = self.detect_multiple(
            cyberrange_pcap, detectors, label='cyberrange'
        )
        
        # 检测基准数据集
        results['baseline'] = {}
        for strategy, pcap_path in baseline_pcaps.items():
            if Path(pcap_path).exists():
                results['baseline'][strategy] = self.detect_multiple(
                    pcap_path, detectors, label=f'baseline_{strategy}'
                )
        
        # 比较结果
        results['comparison'] = self._compare_detection_results(
            results['cyberrange'],
            results['baseline']
        )
        
        return results
    
    def validate_with_ground_truth(self, detection_results: Dict, 
                                 gt_df: pd.DataFrame,
                                 time_tolerance: float = 5.0) -> Dict:
        """
        使用Ground Truth验证检测结果
        
        Args:
            detection_results: IDS检测结果
            gt_df: Ground Truth DataFrame
            time_tolerance: 时间容差（秒）
            
        Returns:
            验证结果
        """
        self.logger.info("Validating detection results with ground truth")
        
        validation_results = {}
        
        for detector_name, detection in detection_results.get('detections', {}).items():
            if not detection.get('success', False):
                continue
            
            alerts = detection.get('result', {}).get('alerts', [])
            
            # 计算检测指标
            metrics = self._calculate_detection_metrics(alerts, gt_df, time_tolerance)
            
            validation_results[detector_name] = {
                'total_alerts': len(alerts),
                'metrics': metrics,
                'confusion_matrix': self._generate_confusion_matrix(alerts, gt_df, time_tolerance)
            }
        
        # 计算最佳检测器
        if validation_results:
            best_detector = max(
                validation_results.items(),
                key=lambda x: x[1]['metrics'].get('f1_score', 0)
            )
            validation_results['best_detector'] = {
                'name': best_detector[0],
                'f1_score': best_detector[1]['metrics']['f1_score']
            }
        
        return validation_results
    
    def _generate_detection_summary(self, detections: Dict) -> Dict:
        """生成检测摘要"""
        summary = {
            'total_detectors': len(detections),
            'successful_detections': sum(1 for d in detections.values() if d.get('success', False)),
            'total_alerts': 0,
            'alert_distribution': {}
        }
        
        for detector_name, detection in detections.items():
            if detection.get('success', False):
                result = detection.get('result', {})
                alert_count = result.get('alert_count', 0)
                summary['total_alerts'] += alert_count
                summary['alert_distribution'][detector_name] = alert_count
        
        return summary
    
    def _compare_detection_results(self, cyberrange_results: Dict, 
                                 baseline_results: Dict) -> Dict:
        """比较检测结果"""
        comparison = {
            'alert_count_comparison': {},
            'detection_consistency': {}
        }
        
        # 比较告警数量
        cr_summary = cyberrange_results.get('summary', {})
        cr_alerts = cr_summary.get('alert_distribution', {})
        
        for strategy, baseline_result in baseline_results.items():
            bl_summary = baseline_result.get('summary', {})
            bl_alerts = bl_summary.get('alert_distribution', {})
            
            comparison['alert_count_comparison'][strategy] = {}
            
            for detector in cr_alerts:
                if detector in bl_alerts:
                    cr_count = cr_alerts[detector]
                    bl_count = bl_alerts[detector]
                    
                    comparison['alert_count_comparison'][strategy][detector] = {
                        'cyberrange': cr_count,
                        'baseline': bl_count,
                        'ratio': cr_count / bl_count if bl_count > 0 else float('inf')
                    }
        
        return comparison
    
    def _calculate_detection_metrics(self, alerts: List[Dict], 
                                   gt_df: pd.DataFrame,
                                   time_tolerance: float) -> Dict:
        """计算检测指标"""
        # 这是一个简化的实现，实际应该更复杂
        true_positives = 0
        false_positives = 0
        false_negatives = 0
        
        # 将GT中的攻击事件提取出来
        attack_events = gt_df[gt_df['label'] == 1].copy()
        attack_events['matched'] = False
        
        # 匹配告警与攻击事件
        for alert in alerts:
            alert_time = alert.get('timestamp')
            if not alert_time:
                continue
            
            # 查找时间窗口内的攻击事件
            matched = False
            for idx, event in attack_events.iterrows():
                if event['matched']:
                    continue
                
                event_time = event['timestamp']
                # 简化的时间匹配逻辑
                if abs((alert_time - event_time).total_seconds()) <= time_tolerance:
                    true_positives += 1
                    attack_events.at[idx, 'matched'] = True
                    matched = True
                    break
            
            if not matched:
                false_positives += 1
        
        # 未匹配的攻击事件是漏报
        false_negatives = len(attack_events[~attack_events['matched']])
        
        # 计算指标
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            'true_positives': true_positives,
            'false_positives': false_positives,
            'false_negatives': false_negatives,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score
        }
    
    def _generate_confusion_matrix(self, alerts: List[Dict], 
                                 gt_df: pd.DataFrame,
                                 time_tolerance: float) -> Dict:
        """生成混淆矩阵"""
        metrics = self._calculate_detection_metrics(alerts, gt_df, time_tolerance)
        
        # 真阴性需要额外计算
        total_benign = len(gt_df[gt_df['label'] == 0])
        true_negatives = total_benign  # 简化假设：所有良性流量都正确识别
        
        return {
            'true_positives': metrics['true_positives'],
            'false_positives': metrics['false_positives'],
            'true_negatives': true_negatives,
            'false_negatives': metrics['false_negatives']
        }
    
    def save_detection_results(self, results: Dict, filename: str = None) -> str:
        """保存检测结果"""
        if filename is None:
            filename = f"ids_detection_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        output_path = self.output_dir / filename
        
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        self.logger.info(f"Detection results saved to: {output_path}")
        return str(output_path)
    
    def get_detector_info(self) -> Dict:
        """获取所有检测器的信息"""
        info = {}
        
        for name, detector in self.detectors.items():
            info[name] = {
                'name': name,
                'version': detector.get_version(),
                'rules_count': detector.get_rules_count(),
                'enabled': detector.is_available()
            }
        
        return info


def main():
    """测试IDS管理器"""
    import argparse
    
    parser = argparse.ArgumentParser(description="IDS Detection Manager")
    parser.add_argument("pcap", help="PCAP file to analyze")
    parser.add_argument("--detectors", nargs='+', 
                       help="Specific detectors to use")
    parser.add_argument("--output", default="./ids_results",
                       help="Output directory")
    
    args = parser.parse_args()
    
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 创建IDS管理器
    manager = IDSManager(args.output)
    
    # 显示检测器信息
    print("\n🔍 Available IDS Detectors:")
    detector_info = manager.get_detector_info()
    for name, info in detector_info.items():
        print(f"  • {name}: v{info['version']} "
              f"({info['rules_count']} rules) "
              f"{'✓' if info['enabled'] else '✗'}")
    
    # 运行检测
    print(f"\n🚀 Running detection on: {args.pcap}")
    results = manager.detect_multiple(args.pcap, args.detectors)
    
    # 显示结果摘要
    summary = results.get('summary', {})
    print(f"\n📊 Detection Summary:")
    print(f"  Total alerts: {summary.get('total_alerts', 0)}")
    print(f"  Alert distribution:")
    for detector, count in summary.get('alert_distribution', {}).items():
        print(f"    • {detector}: {count} alerts")
    
    # 保存结果
    output_file = manager.save_detection_results(results)
    print(f"\n💾 Results saved to: {output_file}")
    
    return 0


if __name__ == "__main__":
    exit(main())
