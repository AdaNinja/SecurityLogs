#!/usr/bin/env python3
"""
Ground Truth Extractor
从nginx detailed.log中提取Ground Truth标签
"""

import pandas as pd
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import numpy as np


class GroundTruthExtractor:
    """Ground Truth提取器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # 定义攻击类型映射
        self.attack_patterns = {
            'sql_injection': [
                'union select', 'or 1=1', 'drop table', 
                'information_schema', '; select', 'concat('
            ],
            'xss': [
                '<script', 'javascript:', 'onerror=', 
                'onload=', 'alert(', 'document.cookie'
            ],
            'path_traversal': [
                '../', '..\\', '%2e%2e', '..../', 
                '/etc/passwd', '/windows/system32'
            ],
            'command_injection': [
                '; cat', '| nc', '&& ls', 'exec(', 
                'system(', 'shell_exec'
            ],
            'ldap_injection': [
                '*)(&', '|(', '*))', 'objectClass='
            ],
            'xxe': [
                '<!ENTITY', 'SYSTEM "file://', '<!DOCTYPE'
            ],
            'file_upload': [
                '.php', '.jsp', '.asp', '.exe', 'multipart/form-data'
            ]
        }
    
    def extract_from_detailed_log(self, log_path: str) -> pd.DataFrame:
        """
        从nginx detailed.log CSV文件中提取GT
        
        Args:
            log_path: detailed.log CSV文件路径
            
        Returns:
            包含GT标签的DataFrame
        """
        self.logger.info(f"Extracting ground truth from: {log_path}")
        
        try:
            # 读取CSV文件
            df = pd.read_csv(log_path)
            
            # 确保必要的列存在
            required_columns = ['timestamp', 'label', 'request_path', 'ip_src', 
                              'response_code', 'request_method', 'payload']
            
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                self.logger.warning(f"Missing columns: {missing_columns}")
            
            # 转换时间戳
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # 提取GT信息
            gt_df = df[['timestamp', 'ip_src', 'request_method', 
                       'request_path', 'response_code', 'label']].copy()
            
            # 添加攻击类型分类
            if 'request_path' in df.columns and 'payload' in df.columns:
                gt_df['attack_type'] = df.apply(self._classify_attack_type, axis=1)
            else:
                gt_df['attack_type'] = 'unknown'
            
            # 统计信息
            total_records = len(gt_df)
            attack_records = len(gt_df[gt_df['label'] == 1])
            benign_records = len(gt_df[gt_df['label'] == 0])
            
            self.logger.info(f"Extracted {total_records} records: "
                           f"{attack_records} attacks, {benign_records} benign")
            
            # 按攻击类型统计
            if 'attack_type' in gt_df.columns:
                attack_type_counts = gt_df[gt_df['label'] == 1]['attack_type'].value_counts()
                self.logger.info("Attack type distribution:")
                for attack_type, count in attack_type_counts.items():
                    self.logger.info(f"  {attack_type}: {count}")
            
            return gt_df
            
        except Exception as e:
            self.logger.error(f"Error extracting ground truth: {e}")
            raise
    
    def _classify_attack_type(self, row) -> str:
        """分类攻击类型"""
        if row.get('label', 0) == 0:
            return 'benign'
        
        request_path = str(row.get('request_path', '')).lower()
        payload = str(row.get('payload', '')).lower()
        combined = request_path + ' ' + payload
        
        # 检查每种攻击类型
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if pattern.lower() in combined:
                    return attack_type
        
        # 基于响应码的额外分类
        response_code = row.get('response_code', 200)
        if response_code >= 500:
            return 'server_error_attack'
        elif response_code == 404:
            return 'scan_attempt'
        
        return 'unknown_attack'
    
    def validate_gt_quality(self, gt_df: pd.DataFrame) -> Dict[str, float]:
        """
        验证GT数据质量
        
        Returns:
            质量指标字典
        """
        quality_metrics = {}
        
        # 1. 完整性检查
        total_records = len(gt_df)
        missing_values = gt_df.isnull().sum().sum()
        quality_metrics['completeness'] = 1 - (missing_values / (total_records * len(gt_df.columns)))
        
        # 2. 标签平衡性
        if 'label' in gt_df.columns:
            attack_ratio = gt_df['label'].sum() / len(gt_df)
            # 理想比例在20%-80%之间
            balance_score = 1 - abs(0.5 - attack_ratio) * 2
            quality_metrics['label_balance'] = max(0, balance_score)
        
        # 3. 时间连续性
        if 'timestamp' in gt_df.columns:
            time_diffs = gt_df['timestamp'].diff().dropna()
            # 检查是否有超过1分钟的间隔
            large_gaps = (time_diffs > pd.Timedelta(minutes=1)).sum()
            quality_metrics['time_continuity'] = 1 - (large_gaps / len(time_diffs))
        
        # 4. 攻击多样性
        if 'attack_type' in gt_df.columns:
            attack_types = gt_df[gt_df['label'] == 1]['attack_type'].nunique()
            # 期望至少有5种不同的攻击类型
            quality_metrics['attack_diversity'] = min(attack_types / 5, 1.0)
        
        # 5. IP多样性
        if 'ip_src' in gt_df.columns:
            unique_ips = gt_df['ip_src'].nunique()
            # 期望至少有10个不同的IP
            quality_metrics['ip_diversity'] = min(unique_ips / 10, 1.0)
        
        # 计算总体质量分数
        quality_metrics['overall_score'] = np.mean(list(quality_metrics.values()))
        
        self.logger.info("Ground Truth quality metrics:")
        for metric, value in quality_metrics.items():
            self.logger.info(f"  {metric}: {value:.3f}")
        
        return quality_metrics
    
    def create_time_windows(self, gt_df: pd.DataFrame, 
                          window_size: int = 60) -> List[Tuple[datetime, datetime, pd.DataFrame]]:
        """
        创建时间窗口用于评估
        
        Args:
            gt_df: GT数据
            window_size: 窗口大小（秒）
            
        Returns:
            (开始时间, 结束时间, 窗口内数据)的列表
        """
        if 'timestamp' not in gt_df.columns:
            return []
        
        gt_df = gt_df.sort_values('timestamp')
        
        min_time = gt_df['timestamp'].min()
        max_time = gt_df['timestamp'].max()
        
        windows = []
        current_time = min_time
        
        while current_time < max_time:
            window_end = current_time + pd.Timedelta(seconds=window_size)
            window_data = gt_df[(gt_df['timestamp'] >= current_time) & 
                              (gt_df['timestamp'] < window_end)]
            
            if not window_data.empty:
                windows.append((current_time, window_end, window_data))
            
            current_time = window_end
        
        self.logger.info(f"Created {len(windows)} time windows of {window_size}s each")
        return windows
    
    def export_for_ids_validation(self, gt_df: pd.DataFrame, 
                                 output_path: str) -> None:
        """
        导出GT数据供IDS验证使用
        
        Args:
            gt_df: GT数据
            output_path: 输出路径
        """
        # 准备IDS验证所需的格式
        ids_gt = gt_df[['timestamp', 'ip_src', 'label', 'attack_type']].copy()
        
        # 添加时间戳的Unix格式
        ids_gt['timestamp_unix'] = ids_gt['timestamp'].astype(int) / 10**9
        
        # 保存为CSV
        ids_gt.to_csv(output_path, index=False)
        self.logger.info(f"Exported GT for IDS validation to: {output_path}")
    
    def generate_summary_report(self, gt_df: pd.DataFrame) -> Dict:
        """生成GT摘要报告"""
        summary = {
            'total_records': len(gt_df),
            'attack_records': int(gt_df['label'].sum()) if 'label' in gt_df.columns else 0,
            'benign_records': int((~gt_df['label'].astype(bool)).sum()) if 'label' in gt_df.columns else 0,
            'time_range': {
                'start': str(gt_df['timestamp'].min()) if 'timestamp' in gt_df.columns else None,
                'end': str(gt_df['timestamp'].max()) if 'timestamp' in gt_df.columns else None,
                'duration': str(gt_df['timestamp'].max() - gt_df['timestamp'].min()) if 'timestamp' in gt_df.columns else None
            }
        }
        
        # 攻击类型分布
        if 'attack_type' in gt_df.columns:
            attack_dist = gt_df[gt_df['label'] == 1]['attack_type'].value_counts().to_dict()
            summary['attack_distribution'] = attack_dist
        
        # 响应码分布
        if 'response_code' in gt_df.columns:
            response_dist = gt_df['response_code'].value_counts().to_dict()
            summary['response_code_distribution'] = response_dist
        
        # IP统计
        if 'ip_src' in gt_df.columns:
            summary['unique_ips'] = gt_df['ip_src'].nunique()
            top_ips = gt_df['ip_src'].value_counts().head(5).to_dict()
            summary['top_5_ips'] = top_ips
        
        return summary


def main():
    """测试GT提取器"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Extract Ground Truth from logs")
    parser.add_argument("log_path", help="Path to nginx detailed.log CSV file")
    parser.add_argument("--output", help="Output path for IDS validation GT")
    parser.add_argument("--validate", action="store_true", 
                       help="Validate GT quality")
    
    args = parser.parse_args()
    
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 创建提取器
    extractor = GroundTruthExtractor()
    
    # 提取GT
    gt_df = extractor.extract_from_detailed_log(args.log_path)
    
    # 验证质量
    if args.validate:
        quality_metrics = extractor.validate_gt_quality(gt_df)
        print(f"\n✅ Overall GT quality score: {quality_metrics['overall_score']:.3f}")
    
    # 导出供IDS验证
    if args.output:
        extractor.export_for_ids_validation(gt_df, args.output)
        print(f"\n✅ Exported GT to: {args.output}")
    
    # 生成摘要
    summary = extractor.generate_summary_report(gt_df)
    print("\n📊 Ground Truth Summary:")
    print(f"  Total records: {summary['total_records']}")
    print(f"  Attack records: {summary['attack_records']}")
    print(f"  Benign records: {summary['benign_records']}")
    
    return 0


if __name__ == "__main__":
    exit(main())
