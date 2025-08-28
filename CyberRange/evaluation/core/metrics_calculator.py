#!/usr/bin/env python3
"""
Metrics Calculator
计算数据集质量的各种指标
"""

import logging
from typing import Dict, List, Tuple, Optional, Any
import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from collections import Counter
import math


class MetricsCalculator:
    """质量指标计算器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # 定义指标权重
        self.default_weights = {
            'detection_accuracy': 0.3,
            'label_quality': 0.25,
            'data_diversity': 0.2,
            'temporal_quality': 0.15,
            'attack_realism': 0.1
        }
    
    def calculate_detection_metrics(self, y_true: List[int], y_pred: List[int]) -> Dict:
        """
        计算检测性能指标
        
        Args:
            y_true: 真实标签
            y_pred: 预测标签
            
        Returns:
            检测指标字典
        """
        if len(y_true) != len(y_pred):
            raise ValueError("True labels and predictions must have same length")
        
        if len(y_true) == 0:
            return {
                'precision': 0,
                'recall': 0,
                'f1_score': 0,
                'accuracy': 0,
                'confusion_matrix': [[0, 0], [0, 0]]
            }
        
        # 计算基础指标
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        # 计算准确率
        accuracy = sum(1 for t, p in zip(y_true, y_pred) if t == p) / len(y_true)
        
        # 混淆矩阵
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        
        # 额外指标
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
        
        # 特异度 (True Negative Rate)
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        
        # 误报率 (False Positive Rate)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        # 漏报率 (False Negative Rate)
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        return {
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'accuracy': float(accuracy),
            'specificity': float(specificity),
            'false_positive_rate': float(fpr),
            'false_negative_rate': float(fnr),
            'confusion_matrix': cm.tolist(),
            'true_positives': int(tp),
            'false_positives': int(fp),
            'true_negatives': int(tn),
            'false_negatives': int(fn)
        }
    
    def calculate_data_diversity(self, data_stats: Dict) -> Dict:
        """
        计算数据多样性指标
        
        Args:
            data_stats: 数据统计信息
            
        Returns:
            多样性指标
        """
        diversity_metrics = {}
        
        # 1. 协议多样性 (使用Shannon熵)
        if 'protocol_distribution' in data_stats:
            protocols = data_stats['protocol_distribution']
            diversity_metrics['protocol_diversity'] = self._calculate_entropy(protocols)
            diversity_metrics['protocol_count'] = len(protocols)
        
        # 2. 端口多样性
        if 'port_distribution' in data_stats:
            ports = data_stats['port_distribution']
            diversity_metrics['port_diversity'] = self._calculate_entropy(ports)
            diversity_metrics['unique_ports'] = len(ports)
        
        # 3. IP地址多样性
        if 'ip_statistics' in data_stats:
            ip_stats = data_stats['ip_statistics']
            diversity_metrics['unique_ips'] = ip_stats.get('unique_count', 0)
            diversity_metrics['ip_entropy'] = ip_stats.get('entropy', 0)
        
        # 4. 攻击类型多样性
        if 'attack_types' in data_stats:
            attack_types = data_stats['attack_types']
            diversity_metrics['attack_type_count'] = len(attack_types)
            diversity_metrics['attack_type_entropy'] = self._calculate_entropy(attack_types)
        
        # 5. 时间分布多样性
        if 'temporal_distribution' in data_stats:
            temporal = data_stats['temporal_distribution']
            diversity_metrics['temporal_variance'] = temporal.get('variance', 0)
            diversity_metrics['burst_ratio'] = temporal.get('burst_ratio', 0)
        
        # 计算综合多样性分数
        diversity_score = self._calculate_diversity_score(diversity_metrics)
        diversity_metrics['overall_diversity_score'] = diversity_score
        
        return diversity_metrics
    
    def calculate_label_quality(self, gt_stats: Dict, validation_results: Dict) -> Dict:
        """
        计算标签质量指标
        
        Args:
            gt_stats: Ground Truth统计信息
            validation_results: 验证结果
            
        Returns:
            标签质量指标
        """
        label_metrics = {}
        
        # 1. 标签完整性
        total_events = gt_stats.get('total_events', 0)
        labeled_events = gt_stats.get('labeled_events', total_events)
        label_metrics['completeness'] = labeled_events / total_events if total_events > 0 else 0
        
        # 2. 标签平衡性
        attack_ratio = gt_stats.get('attack_ratio', 0)
        # 理想的攻击比例在20%-50%之间
        if 0.2 <= attack_ratio <= 0.5:
            balance_score = 1.0
        elif attack_ratio < 0.2:
            balance_score = attack_ratio / 0.2
        else:
            balance_score = 1 - (attack_ratio - 0.5) / 0.5
        label_metrics['balance_score'] = balance_score
        
        # 3. 标签一致性（与IDS检测的一致性）
        if validation_results:
            consistency_scores = []
            for detector, results in validation_results.items():
                if 'metrics' in results:
                    # 使用F1分数作为一致性指标
                    consistency_scores.append(results['metrics'].get('f1_score', 0))
            
            if consistency_scores:
                label_metrics['consistency_score'] = np.mean(consistency_scores)
            else:
                label_metrics['consistency_score'] = 0
        
        # 4. 标签粒度（攻击类型的详细程度）
        attack_types = gt_stats.get('attack_type_count', 0)
        # 期望至少有5种不同的攻击类型
        label_metrics['granularity_score'] = min(attack_types / 5, 1.0)
        
        # 计算综合标签质量分数
        label_quality_score = np.mean([
            label_metrics['completeness'],
            label_metrics['balance_score'],
            label_metrics.get('consistency_score', 0),
            label_metrics['granularity_score']
        ])
        label_metrics['overall_label_quality'] = label_quality_score
        
        return label_metrics
    
    def calculate_temporal_quality(self, temporal_stats: Dict) -> Dict:
        """
        计算时间质量指标
        
        Args:
            temporal_stats: 时间统计信息
            
        Returns:
            时间质量指标
        """
        temporal_metrics = {}
        
        # 1. 时间连续性
        if 'max_gap' in temporal_stats:
            max_gap = temporal_stats['max_gap']
            # 超过60秒的间隔认为是不连续的
            continuity_score = 1 - min(max_gap / 60, 1.0)
            temporal_metrics['continuity_score'] = continuity_score
        
        # 2. 时间覆盖率
        if 'duration' in temporal_stats and 'active_duration' in temporal_stats:
            duration = temporal_stats['duration']
            active_duration = temporal_stats['active_duration']
            coverage = active_duration / duration if duration > 0 else 0
            temporal_metrics['coverage_score'] = coverage
        
        # 3. 流量分布均匀性
        if 'packet_rate_variance' in temporal_stats:
            variance = temporal_stats['packet_rate_variance']
            mean_rate = temporal_stats.get('mean_packet_rate', 1)
            # 计算变异系数
            cv = math.sqrt(variance) / mean_rate if mean_rate > 0 else float('inf')
            # CV越小越均匀
            uniformity_score = 1 / (1 + cv)
            temporal_metrics['uniformity_score'] = uniformity_score
        
        # 4. 突发流量检测
        if 'burst_count' in temporal_stats:
            burst_count = temporal_stats['burst_count']
            total_windows = temporal_stats.get('total_windows', 1)
            burst_ratio = burst_count / total_windows
            # 适度的突发是正常的
            if burst_ratio <= 0.1:
                burst_score = 1.0
            else:
                burst_score = 1 - min(burst_ratio - 0.1, 0.9)
            temporal_metrics['burst_score'] = burst_score
        
        # 计算综合时间质量分数
        scores = [v for k, v in temporal_metrics.items() if k.endswith('_score')]
        temporal_metrics['overall_temporal_quality'] = np.mean(scores) if scores else 0
        
        return temporal_metrics
    
    def calculate_attack_realism(self, attack_stats: Dict, baseline_stats: Dict = None) -> Dict:
        """
        计算攻击真实性指标
        
        Args:
            attack_stats: 攻击统计信息
            baseline_stats: 基准统计信息（可选）
            
        Returns:
            攻击真实性指标
        """
        realism_metrics = {}
        
        # 1. 攻击模式真实性
        if 'attack_patterns' in attack_stats:
            patterns = attack_stats['attack_patterns']
            # 检查是否包含真实的攻击模式
            real_patterns = ['slow_rate', 'burst', 'scanning', 'exploitation']
            pattern_matches = sum(1 for p in real_patterns if p in patterns)
            realism_metrics['pattern_realism'] = pattern_matches / len(real_patterns)
        
        # 2. 攻击强度真实性
        if 'attack_intensity' in attack_stats:
            intensity = attack_stats['attack_intensity']
            # 真实攻击通常不会太极端
            if 0.1 <= intensity <= 0.8:
                intensity_score = 1.0
            else:
                intensity_score = 0.5
            realism_metrics['intensity_realism'] = intensity_score
        
        # 3. 与基准的相似度（如果有基准数据）
        if baseline_stats:
            similarity_scores = []
            
            # 比较各种分布
            for key in ['protocol_distribution', 'port_distribution', 'attack_types']:
                if key in attack_stats and key in baseline_stats:
                    similarity = self._calculate_distribution_similarity(
                        attack_stats[key],
                        baseline_stats[key]
                    )
                    similarity_scores.append(similarity)
            
            if similarity_scores:
                realism_metrics['baseline_similarity'] = np.mean(similarity_scores)
        
        # 4. 攻击序列真实性
        if 'attack_sequence' in attack_stats:
            sequence = attack_stats['attack_sequence']
            # 检查攻击序列是否符合真实攻击的阶段
            # 侦察 -> 扫描 -> 利用 -> 后渗透
            sequence_score = self._evaluate_attack_sequence(sequence)
            realism_metrics['sequence_realism'] = sequence_score
        
        # 计算综合真实性分数
        scores = [v for k, v in realism_metrics.items() if isinstance(v, (int, float))]
        realism_metrics['overall_realism_score'] = np.mean(scores) if scores else 0
        
        return realism_metrics
    
    def calculate_overall_quality_score(self, all_metrics: Dict, 
                                      weights: Dict = None) -> Dict:
        """
        计算总体质量分数
        
        Args:
            all_metrics: 所有指标
            weights: 权重（可选）
            
        Returns:
            总体质量评分
        """
        if weights is None:
            weights = self.default_weights
        
        quality_components = {}
        
        # 提取各个维度的分数
        if 'detection_metrics' in all_metrics:
            quality_components['detection_accuracy'] = all_metrics['detection_metrics'].get('f1_score', 0)
        
        if 'label_metrics' in all_metrics:
            quality_components['label_quality'] = all_metrics['label_metrics'].get('overall_label_quality', 0)
        
        if 'diversity_metrics' in all_metrics:
            quality_components['data_diversity'] = all_metrics['diversity_metrics'].get('overall_diversity_score', 0)
        
        if 'temporal_metrics' in all_metrics:
            quality_components['temporal_quality'] = all_metrics['temporal_metrics'].get('overall_temporal_quality', 0)
        
        if 'realism_metrics' in all_metrics:
            quality_components['attack_realism'] = all_metrics['realism_metrics'].get('overall_realism_score', 0)
        
        # 计算加权分数
        weighted_sum = 0
        total_weight = 0
        
        for component, score in quality_components.items():
            if component in weights:
                weight = weights[component]
                weighted_sum += score * weight
                total_weight += weight
        
        overall_score = weighted_sum / total_weight if total_weight > 0 else 0
        
        # 计算质量等级
        grade = self._calculate_grade(overall_score)
        
        return {
            'components': quality_components,
            'weights': weights,
            'overall_score': overall_score,
            'grade': grade,
            'recommendation': self._generate_recommendation(quality_components)
        }
    
    def _calculate_entropy(self, distribution: Dict) -> float:
        """计算Shannon熵"""
        if not distribution:
            return 0
        
        total = sum(distribution.values())
        if total == 0:
            return 0
        
        entropy = 0
        for count in distribution.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _calculate_diversity_score(self, diversity_metrics: Dict) -> float:
        """计算综合多样性分数"""
        scores = []
        
        # 归一化各个多样性指标
        if 'protocol_diversity' in diversity_metrics:
            # 期望至少2比特的熵
            scores.append(min(diversity_metrics['protocol_diversity'] / 2, 1.0))
        
        if 'port_diversity' in diversity_metrics:
            # 期望至少3比特的熵
            scores.append(min(diversity_metrics['port_diversity'] / 3, 1.0))
        
        if 'unique_ips' in diversity_metrics:
            # 期望至少20个不同的IP
            scores.append(min(diversity_metrics['unique_ips'] / 20, 1.0))
        
        if 'attack_type_count' in diversity_metrics:
            # 期望至少5种攻击类型
            scores.append(min(diversity_metrics['attack_type_count'] / 5, 1.0))
        
        return np.mean(scores) if scores else 0
    
    def _calculate_distribution_similarity(self, dist1: Dict, dist2: Dict) -> float:
        """计算两个分布的相似度"""
        if not dist1 or not dist2:
            return 0
        
        # 使用Jaccard相似度
        keys1 = set(dist1.keys())
        keys2 = set(dist2.keys())
        
        intersection = keys1.intersection(keys2)
        union = keys1.union(keys2)
        
        if not union:
            return 0
        
        jaccard = len(intersection) / len(union)
        
        # 考虑数值的相似度
        if intersection:
            value_similarities = []
            for key in intersection:
                v1 = dist1[key]
                v2 = dist2[key]
                if v1 + v2 > 0:
                    similarity = 1 - abs(v1 - v2) / (v1 + v2)
                    value_similarities.append(similarity)
            
            if value_similarities:
                value_similarity = np.mean(value_similarities)
                return (jaccard + value_similarity) / 2
        
        return jaccard
    
    def _evaluate_attack_sequence(self, sequence: List[str]) -> float:
        """评估攻击序列的真实性"""
        # 定义真实的攻击阶段
        real_stages = ['reconnaissance', 'scanning', 'exploitation', 'post_exploitation']
        
        if not sequence:
            return 0
        
        # 检查序列是否包含这些阶段
        stage_found = [False] * len(real_stages)
        
        for i, stage in enumerate(real_stages):
            for attack in sequence:
                if stage in attack.lower():
                    stage_found[i] = True
                    break
        
        # 检查顺序是否合理
        order_score = 1.0
        last_found = -1
        for i, found in enumerate(stage_found):
            if found:
                if last_found >= 0 and i < last_found:
                    order_score *= 0.8  # 顺序错误的惩罚
                last_found = i
        
        coverage = sum(stage_found) / len(real_stages)
        
        return coverage * order_score
    
    def _calculate_grade(self, score: float) -> str:
        """根据分数计算等级"""
        if score >= 0.95:
            return "A+"
        elif score >= 0.90:
            return "A"
        elif score >= 0.85:
            return "A-"
        elif score >= 0.80:
            return "B+"
        elif score >= 0.75:
            return "B"
        elif score >= 0.70:
            return "B-"
        elif score >= 0.65:
            return "C+"
        elif score >= 0.60:
            return "C"
        elif score >= 0.55:
            return "C-"
        elif score >= 0.50:
            return "D"
        else:
            return "F"
    
    def _generate_recommendation(self, components: Dict) -> str:
        """生成改进建议"""
        # 找出最低的组件
        if not components:
            return "No data available for recommendations"
        
        min_component = min(components.items(), key=lambda x: x[1])
        min_name, min_score = min_component
        
        recommendations = {
            'detection_accuracy': "Improve IDS rules or add more attack signatures",
            'label_quality': "Review and refine ground truth labels, ensure balanced dataset",
            'data_diversity': "Add more varied attack types and network protocols",
            'temporal_quality': "Ensure continuous traffic flow and reduce time gaps",
            'attack_realism': "Make attacks more realistic and follow real-world patterns"
        }
        
        base_recommendation = recommendations.get(min_name, "General quality improvement needed")
        
        if min_score < 0.5:
            severity = "Critical"
        elif min_score < 0.7:
            severity = "Important"
        else:
            severity = "Minor"
        
        return f"{severity}: {base_recommendation} (current score: {min_score:.2f})"


def main():
    """测试指标计算器"""
    # 创建示例数据
    y_true = [0, 1, 1, 0, 1, 0, 1, 1, 0, 0]
    y_pred = [0, 1, 0, 0, 1, 1, 1, 1, 0, 0]
    
    calculator = MetricsCalculator()
    
    # 测试检测指标
    detection_metrics = calculator.calculate_detection_metrics(y_true, y_pred)
    
    print("Detection Metrics:")
    print(f"  Precision: {detection_metrics['precision']:.3f}")
    print(f"  Recall: {detection_metrics['recall']:.3f}")
    print(f"  F1-Score: {detection_metrics['f1_score']:.3f}")
    print(f"  Accuracy: {detection_metrics['accuracy']:.3f}")
    
    # 测试其他指标...
    
    return 0


if __name__ == "__main__":
    exit(main())
