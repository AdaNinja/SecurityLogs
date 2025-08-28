#!/usr/bin/env python3
"""
Dataset Evaluator
数据集质量评估主类，协调各个组件完成评估任务
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
import pandas as pd
import numpy as np
from datetime import datetime
import json

from .pcap_analyzer import PCAPAnalyzer
from .gt_extractor import GroundTruthExtractor


class DatasetEvaluator:
    """数据集评估器主类"""
    
    def __init__(self, output_dir: str = "./evaluation_results", max_packets: int = 5000):
        """
        初始化评估器
        
        Args:
            output_dir: 评估结果输出目录
            max_packets: 最大分析数据包数量
        """
        self.logger = logging.getLogger(__name__)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_packets = max_packets
        
        # 初始化组件
        self.pcap_analyzer = PCAPAnalyzer()
        self.pcap_analyzer.max_packets = max_packets  # 设置数据包限制
        self.gt_extractor = GroundTruthExtractor()
        
        # 评估结果存储
        self.evaluation_results = {
            'timestamp': datetime.now().isoformat(),
            'cyberrange': {},
            'baseline': {},
            'comparison': {},
            'quality_scores': {}
        }
        
        self.logger.info(f"Dataset evaluator initialized. Output: {self.output_dir}")
    
    def evaluate_cyberrange_dataset(self, pcap_path: str, gt_log_path: str) -> Dict:
        """
        评估CyberRange生成的数据集
        
        Args:
            pcap_path: CyberRange PCAP文件路径
            gt_log_path: nginx detailed.log CSV文件路径
            
        Returns:
            评估结果字典
        """
        self.logger.info("Starting CyberRange dataset evaluation")
        
        cyberrange_eval = {
            'pcap_analysis': {},
            'ground_truth': {},
            'data_quality': {}
        }
        
        # 1. 分析PCAP文件
        self.logger.info("Analyzing CyberRange PCAP...")
        cyberrange_eval['pcap_analysis'] = self.pcap_analyzer.analyze_pcap(pcap_path)
        
        # 2. 提取和验证Ground Truth
        self.logger.info("Extracting ground truth labels...")
        gt_df = self.gt_extractor.extract_from_detailed_log(gt_log_path)
        cyberrange_eval['ground_truth']['summary'] = self.gt_extractor.generate_summary_report(gt_df)
        cyberrange_eval['ground_truth']['quality'] = self.gt_extractor.validate_gt_quality(gt_df)
        
        # 3. 评估数据质量
        cyberrange_eval['data_quality'] = self._assess_data_quality(
            cyberrange_eval['pcap_analysis'],
            cyberrange_eval['ground_truth']
        )
        
        # 保存GT供后续IDS验证使用
        gt_export_path = self.output_dir / "cyberrange_gt.csv"
        self.gt_extractor.export_for_ids_validation(gt_df, str(gt_export_path))
        
        self.evaluation_results['cyberrange'] = cyberrange_eval
        return cyberrange_eval
    
    def evaluate_baseline_datasets(self, baseline_pcaps: Dict[str, str]) -> Dict:
        """
        评估基准数据集（Fiberfox生成的PCAP）
        
        Args:
            baseline_pcaps: 策略名到PCAP路径的映射
            
        Returns:
            基准数据集评估结果
        """
        self.logger.info("Evaluating baseline datasets")
        
        baseline_eval = {}
        
        for strategy, pcap_path in baseline_pcaps.items():
            if not Path(pcap_path).exists():
                self.logger.warning(f"Baseline PCAP not found: {pcap_path}")
                continue
            
            self.logger.info(f"Analyzing {strategy} baseline PCAP...")
            baseline_eval[strategy] = {
                'pcap_analysis': self.pcap_analyzer.analyze_pcap(pcap_path),
                'expected_characteristics': self._get_expected_characteristics(strategy)
            }
        
        self.evaluation_results['baseline'] = baseline_eval
        return baseline_eval
    
    def compare_datasets(self, cyberrange_pcap: str, baseline_pcaps: Dict[str, str]) -> Dict:
        """
        比较CyberRange数据集与基准数据集
        
        Args:
            cyberrange_pcap: CyberRange PCAP路径
            baseline_pcaps: 基准PCAP路径字典
            
        Returns:
            比较结果
        """
        self.logger.info("Comparing CyberRange with baseline datasets")
        
        comparison_results = {
            'individual_comparisons': {},
            'aggregated_metrics': {}
        }
        
        similarities = []
        
        for strategy, baseline_pcap in baseline_pcaps.items():
            if not Path(baseline_pcap).exists():
                continue
            
            self.logger.info(f"Comparing with {strategy} baseline...")
            comparison = self.pcap_analyzer.compare_pcaps(cyberrange_pcap, baseline_pcap)
            comparison_results['individual_comparisons'][strategy] = comparison
            
            if 'overall_similarity' in comparison:
                similarities.append(comparison['overall_similarity'])
        
        # 计算聚合指标
        if similarities:
            comparison_results['aggregated_metrics'] = {
                'avg_similarity': np.mean(similarities),
                'max_similarity': np.max(similarities),
                'min_similarity': np.min(similarities),
                'similarity_variance': np.var(similarities)
            }
        
        self.evaluation_results['comparison'] = comparison_results
        return comparison_results
    
    def calculate_quality_scores(self) -> Dict:
        """
        计算综合质量分数
        
        Returns:
            质量分数字典
        """
        self.logger.info("Calculating quality scores")
        
        scores = {
            'components': {},
            'overall': 0
        }
        
        # 1. PCAP质量分数（基于异常检测）
        if 'cyberrange' in self.evaluation_results:
            pcap_analysis = self.evaluation_results['cyberrange'].get('pcap_analysis', {})
            anomaly_score = pcap_analysis.get('anomaly_indicators', {}).get('anomaly_score', 0)
            # 异常分数越高，质量分数越低
            scores['components']['pcap_quality'] = 1 - anomaly_score
        
        # 2. Ground Truth质量分数
        if 'cyberrange' in self.evaluation_results:
            gt_quality = self.evaluation_results['cyberrange'].get('ground_truth', {}).get('quality', {})
            scores['components']['gt_quality'] = gt_quality.get('overall_score', 0)
        
        # 3. 数据多样性分数
        if 'cyberrange' in self.evaluation_results:
            data_quality = self.evaluation_results['cyberrange'].get('data_quality', {})
            scores['components']['data_diversity'] = data_quality.get('diversity_score', 0)
        
        # 4. 与基准的相似度分数
        if 'comparison' in self.evaluation_results:
            agg_metrics = self.evaluation_results['comparison'].get('aggregated_metrics', {})
            # 适度的相似度最好（太高可能是复制，太低可能质量差）
            avg_sim = agg_metrics.get('avg_similarity', 0)
            if avg_sim > 0:
                # 最佳相似度在0.6-0.8之间
                if 0.6 <= avg_sim <= 0.8:
                    sim_score = 1.0
                elif avg_sim < 0.6:
                    sim_score = avg_sim / 0.6
                else:
                    sim_score = 1 - (avg_sim - 0.8) / 0.2
                scores['components']['baseline_similarity'] = sim_score
        
        # 5. 攻击覆盖率分数
        if 'cyberrange' in self.evaluation_results:
            gt_summary = self.evaluation_results['cyberrange'].get('ground_truth', {}).get('summary', {})
            attack_types = len(gt_summary.get('attack_distribution', {}))
            # 期望至少5种攻击类型
            scores['components']['attack_coverage'] = min(attack_types / 5, 1.0)
        
        # 计算加权总分
        weights = {
            'pcap_quality': 0.2,
            'gt_quality': 0.25,
            'data_diversity': 0.2,
            'baseline_similarity': 0.2,
            'attack_coverage': 0.15
        }
        
        weighted_sum = 0
        total_weight = 0
        
        for component, score in scores['components'].items():
            if component in weights:
                weighted_sum += score * weights[component]
                total_weight += weights[component]
        
        if total_weight > 0:
            scores['overall'] = weighted_sum / total_weight
        
        # 评级
        scores['grade'] = self._calculate_grade(scores['overall'])
        
        self.evaluation_results['quality_scores'] = scores
        return scores
    
    def _assess_data_quality(self, pcap_analysis: Dict, ground_truth: Dict) -> Dict:
        """评估数据质量的内部方法"""
        quality_assessment = {
            'completeness': 1.0,
            'consistency': 1.0,
            'diversity_score': 0.0,
            'temporal_quality': 1.0
        }
        
        # 完整性检查
        if pcap_analysis.get('basic_stats', {}).get('total_packets', 0) == 0:
            quality_assessment['completeness'] = 0
        
        # 一致性检查（PCAP时长与GT记录时间范围）
        pcap_duration = pcap_analysis.get('basic_stats', {}).get('duration', 0)
        gt_duration = ground_truth.get('summary', {}).get('time_range', {}).get('duration', '0')
        
        # 多样性评分
        protocol_count = len(pcap_analysis.get('protocol_distribution', {}).get('protocols', {}))
        port_count = len(pcap_analysis.get('protocol_distribution', {}).get('ports', {}))
        attack_count = len(ground_truth.get('summary', {}).get('attack_distribution', {}))
        
        diversity_factors = [
            min(protocol_count / 5, 1.0),    # 期望至少5种协议
            min(port_count / 10, 1.0),        # 期望至少10个端口
            min(attack_count / 5, 1.0)        # 期望至少5种攻击
        ]
        quality_assessment['diversity_score'] = np.mean(diversity_factors)
        
        # 时间质量（检查是否有异常的时间间隔）
        temporal = pcap_analysis.get('temporal_analysis', {})
        if temporal.get('max_packet_interval', 0) > 60:  # 超过60秒的间隔
            quality_assessment['temporal_quality'] = 0.8
        
        return quality_assessment
    
    def _get_expected_characteristics(self, strategy: str) -> Dict:
        """获取特定攻击策略的预期特征"""
        # 这里可以从fiberfox_configs导入
        characteristics = {
            "SLOW": {
                "expected_pattern": "low_bandwidth_persistent",
                "typical_duration": ">60s",
                "packet_rate": "low"
            },
            "GET": {
                "expected_pattern": "high_bandwidth_burst", 
                "typical_duration": "30-60s",
                "packet_rate": "high"
            },
            "BYPASS": {
                "expected_pattern": "moderate_varied",
                "typical_duration": "60-90s",
                "packet_rate": "moderate"
            },
            "AVB": {
                "expected_pattern": "moderate_targeted",
                "typical_duration": "60-90s", 
                "packet_rate": "moderate"
            }
        }
        return characteristics.get(strategy, {})
    
    def _calculate_grade(self, score: float) -> str:
        """根据分数计算等级"""
        if score >= 0.9:
            return "A+"
        elif score >= 0.85:
            return "A"
        elif score >= 0.8:
            return "A-"
        elif score >= 0.75:
            return "B+"
        elif score >= 0.7:
            return "B"
        elif score >= 0.65:
            return "B-"
        elif score >= 0.6:
            return "C+"
        elif score >= 0.55:
            return "C"
        elif score >= 0.5:
            return "C-"
        elif score >= 0.45:
            return "D"
        else:
            return "F"
    
    def save_evaluation_results(self) -> str:
        """
        保存评估结果
        
        Returns:
            结果文件路径
        """
        output_file = self.output_dir / f"evaluation_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(self.evaluation_results, f, indent=2, default=str)
        
        self.logger.info(f"Evaluation results saved to: {output_file}")
        return str(output_file)
    
    def generate_summary(self) -> Dict:
        """生成评估摘要"""
        summary = {
            'evaluation_time': self.evaluation_results['timestamp'],
            'dataset': 'CyberRange',
            'quality_score': self.evaluation_results.get('quality_scores', {}).get('overall', 0),
            'grade': self.evaluation_results.get('quality_scores', {}).get('grade', 'N/A'),
            'key_findings': []
        }
        
        # 添加关键发现
        if 'cyberrange' in self.evaluation_results:
            pcap_stats = self.evaluation_results['cyberrange'].get('pcap_analysis', {}).get('basic_stats', {})
            summary['total_packets'] = pcap_stats.get('total_packets', 0)
            summary['duration_seconds'] = pcap_stats.get('duration', 0)
            
            gt_summary = self.evaluation_results['cyberrange'].get('ground_truth', {}).get('summary', {})
            summary['total_events'] = gt_summary.get('total_records', 0)
            summary['attack_ratio'] = (gt_summary.get('attack_records', 0) / 
                                     gt_summary.get('total_records', 1))
        
        # 关键发现
        quality_scores = self.evaluation_results.get('quality_scores', {}).get('components', {})
        
        # 找出最好和最差的方面
        if quality_scores:
            best_aspect = max(quality_scores.items(), key=lambda x: x[1])
            worst_aspect = min(quality_scores.items(), key=lambda x: x[1])
            
            summary['key_findings'].append(
                f"Strongest aspect: {best_aspect[0]} (score: {best_aspect[1]:.2f})"
            )
            summary['key_findings'].append(
                f"Weakest aspect: {worst_aspect[0]} (score: {worst_aspect[1]:.2f})"
            )
        
        # 异常检测
        anomalies = (self.evaluation_results.get('cyberrange', {})
                    .get('pcap_analysis', {})
                    .get('anomaly_indicators', {}))
        
        if anomalies:
            anomaly_flags = [k for k, v in anomalies.items() if v is True and k != 'anomaly_score']
            if anomaly_flags:
                summary['key_findings'].append(f"Detected anomalies: {', '.join(anomaly_flags)}")
        
        return summary


def main():
    """测试数据集评估器"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Evaluate CyberRange dataset quality")
    parser.add_argument("--cyberrange-pcap", required=True,
                       help="Path to CyberRange PCAP file")
    parser.add_argument("--cyberrange-gt", required=True,
                       help="Path to nginx detailed.log CSV file")
    parser.add_argument("--baseline-dir", 
                       help="Directory containing baseline PCAPs")
    parser.add_argument("--output", default="./evaluation_results",
                       help="Output directory for results")
    
    args = parser.parse_args()
    
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 创建评估器
    evaluator = DatasetEvaluator(args.output)
    
    # 评估CyberRange数据集
    print("\n🎯 Evaluating CyberRange Dataset...")
    cyberrange_eval = evaluator.evaluate_cyberrange_dataset(
        args.cyberrange_pcap,
        args.cyberrange_gt
    )
    
    # 评估基准数据集（如果提供）
    if args.baseline_dir:
        baseline_dir = Path(args.baseline_dir)
        baseline_pcaps = {}
        
        for strategy in ['slow', 'get', 'bypass', 'avb']:
            pcap_path = baseline_dir / f"fiberfox_{strategy}.pcap"
            if pcap_path.exists():
                baseline_pcaps[strategy.upper()] = str(pcap_path)
        
        if baseline_pcaps:
            print("\n📊 Evaluating baseline datasets...")
            evaluator.evaluate_baseline_datasets(baseline_pcaps)
            
            print("\n🔄 Comparing datasets...")
            evaluator.compare_datasets(args.cyberrange_pcap, baseline_pcaps)
    
    # 计算质量分数
    print("\n📈 Calculating quality scores...")
    scores = evaluator.calculate_quality_scores()
    
    # 保存结果
    result_file = evaluator.save_evaluation_results()
    
    # 生成并显示摘要
    summary = evaluator.generate_summary()
    
    print("\n" + "="*60)
    print("📊 EVALUATION SUMMARY")
    print("="*60)
    print(f"Dataset: {summary['dataset']}")
    print(f"Quality Score: {summary['quality_score']:.2%}")
    print(f"Grade: {summary['grade']}")
    print(f"\nKey Findings:")
    for finding in summary['key_findings']:
        print(f"  • {finding}")
    print(f"\nFull results saved to: {result_file}")
    print("="*60)
    
    return 0


if __name__ == "__main__":
    exit(main())
