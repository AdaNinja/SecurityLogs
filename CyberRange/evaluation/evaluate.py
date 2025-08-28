#!/usr/bin/env python3
"""
CyberRange Dataset Quality Evaluation Tool
评估CyberRange生成的数据集质量的主程序
"""

import argparse
import logging
import sys
from pathlib import Path
from datetime import datetime
import json
import yaml

# 添加模块路径
sys.path.append(str(Path(__file__).parent.parent))

from evaluation.core.dataset_evaluator import DatasetEvaluator
from evaluation.core.metrics_calculator import MetricsCalculator
from evaluation.baseline.fiberfox_generator import FiberfoxGenerator
from evaluation.detection.ids_manager import IDSManager
from evaluation.core.gt_extractor import GroundTruthExtractor


class CyberRangeEvaluator:
    """CyberRange数据集评估主类"""
    
    def __init__(self, config_path: str):
        """
        初始化评估器
        
        Args:
            config_path: 配置文件路径
        """
        self.config = self._load_config(config_path)
        self._setup_logging()
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("="*60)
        self.logger.info("CyberRange Dataset Quality Evaluation Tool")
        self.logger.info("="*60)
        
        # 初始化输出目录
        self.output_dir = Path(self.config['output']['directory'])
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 初始化组件
        self.dataset_evaluator = DatasetEvaluator(str(self.output_dir / 'evaluation'))
        self.metrics_calculator = MetricsCalculator()
        self.ids_manager = IDSManager(str(self.output_dir / 'ids_results'))
        self.gt_extractor = GroundTruthExtractor()
        
        # Fiberfox生成器（可选）
        self.fiberfox_generator = None
        if self.config.get('baseline', {}).get('generate_fiberfox', False):
            self.fiberfox_generator = FiberfoxGenerator(
                output_dir=str(self.output_dir / 'baseline_pcaps')
            )
    
    def _load_config(self, config_path: str) -> dict:
        """加载配置文件"""
        with open(config_path, 'r') as f:
            if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                return yaml.safe_load(f)
            else:
                return json.load(f)
    
    def _setup_logging(self):
        """设置日志"""
        log_level = getattr(logging, self.config.get('logging', {}).get('level', 'INFO'))
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        # 控制台日志
        logging.basicConfig(level=log_level, format=log_format)
        
        # 文件日志
        if self.config.get('logging', {}).get('file'):
            log_file = Path(self.config['output']['directory']) / 'evaluation.log'
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(logging.Formatter(log_format))
            logging.getLogger().addHandler(file_handler)
    
    def run_evaluation(self):
        """运行完整的评估流程"""
        evaluation_results = {
            'timestamp': datetime.now().isoformat(),
            'config': self.config,
            'results': {}
        }
        
        try:
            # Step 1: 生成或获取基准数据集
            baseline_pcaps = self._prepare_baseline_datasets()
            
            # Step 2: 评估CyberRange数据集
            self.logger.info("\n" + "="*40)
            self.logger.info("Step 2: Evaluating CyberRange Dataset")
            self.logger.info("="*40)
            
            cyberrange_eval = self.dataset_evaluator.evaluate_cyberrange_dataset(
                self.config['datasets']['cyberrange']['pcap_path'],
                self.config['datasets']['cyberrange']['gt_log_path']
            )
            evaluation_results['results']['cyberrange'] = cyberrange_eval
            
            # Step 3: 评估基准数据集
            if baseline_pcaps:
                self.logger.info("\n" + "="*40)
                self.logger.info("Step 3: Evaluating Baseline Datasets")
                self.logger.info("="*40)
                
                baseline_eval = self.dataset_evaluator.evaluate_baseline_datasets(baseline_pcaps)
                evaluation_results['results']['baseline'] = baseline_eval
                
                # Step 4: 比较数据集
                self.logger.info("\n" + "="*40)
                self.logger.info("Step 4: Comparing Datasets")
                self.logger.info("="*40)
                
                comparison = self.dataset_evaluator.compare_datasets(
                    self.config['datasets']['cyberrange']['pcap_path'],
                    baseline_pcaps
                )
                evaluation_results['results']['comparison'] = comparison
            
            # Step 5: IDS检测评估
            if self.config.get('detection', {}).get('enabled', True):
                self.logger.info("\n" + "="*40)
                self.logger.info("Step 5: Running IDS Detection")
                self.logger.info("="*40)
                
                detection_results = self._run_ids_detection(baseline_pcaps)
                evaluation_results['results']['detection'] = detection_results
            
            # Step 6: 计算综合质量分数
            self.logger.info("\n" + "="*40)
            self.logger.info("Step 6: Calculating Quality Scores")
            self.logger.info("="*40)
            
            quality_scores = self.dataset_evaluator.calculate_quality_scores()
            evaluation_results['results']['quality_scores'] = quality_scores
            
            # Step 7: 生成报告
            self.logger.info("\n" + "="*40)
            self.logger.info("Step 7: Generating Reports")
            self.logger.info("="*40)
            
            self._generate_reports(evaluation_results)
            
            # 保存完整结果
            self._save_results(evaluation_results)
            
            # 显示摘要
            self._display_summary(evaluation_results)
            
        except Exception as e:
            self.logger.error(f"Evaluation failed: {e}")
            raise
    
    def _prepare_baseline_datasets(self) -> dict:
        """准备基准数据集"""
        baseline_pcaps = {}
        
        # 检查是否需要生成Fiberfox数据
        if self.config.get('baseline', {}).get('generate_fiberfox', False):
            self.logger.info("\n" + "="*40)
            self.logger.info("Step 1: Generating Fiberfox Baseline")
            self.logger.info("="*40)
            
            target_url = self.config['baseline']['target_url']
            duration = self.config['baseline'].get('duration', 60)
            
            # 验证Fiberfox安装
            if not self.fiberfox_generator.verify_fiberfox_installation():
                self.logger.error("Fiberfox verification failed")
                return baseline_pcaps
            
            # 生成所有策略的PCAP
            generated = self.fiberfox_generator.generate_all_pcaps(target_url, duration)
            baseline_pcaps.update({k: str(v) for k, v in generated.items()})
            
        else:
            # 使用已有的基准PCAP
            self.logger.info("\n" + "="*40)
            self.logger.info("Step 1: Loading Existing Baseline PCAPs")
            self.logger.info("="*40)
            
            baseline_config = self.config.get('baseline', {}).get('existing_pcaps', {})
            for strategy, pcap_path in baseline_config.items():
                if Path(pcap_path).exists():
                    baseline_pcaps[strategy] = pcap_path
                    self.logger.info(f"Loaded {strategy}: {pcap_path}")
                else:
                    self.logger.warning(f"Baseline PCAP not found: {pcap_path}")
        
        return baseline_pcaps
    
    def _run_ids_detection(self, baseline_pcaps: dict) -> dict:
        """运行IDS检测"""
        detection_config = self.config.get('detection', {})
        enabled_detectors = [d for d, enabled in detection_config.get('detectors', {}).items() if enabled]
        
        if not enabled_detectors:
            self.logger.warning("No IDS detectors enabled")
            return {}
        
        # 检测CyberRange和基准数据集
        results = self.ids_manager.detect_dataset_pair(
            self.config['datasets']['cyberrange']['pcap_path'],
            baseline_pcaps,
            enabled_detectors
        )
        
        # 使用GT验证检测结果
        gt_df = self.gt_extractor.extract_from_detailed_log(
            self.config['datasets']['cyberrange']['gt_log_path']
        )
        
        validation = self.ids_manager.validate_with_ground_truth(
            results['cyberrange'],
            gt_df,
            detection_config.get('time_tolerance', 5.0)
        )
        
        results['validation'] = validation
        
        return results
    
    def _generate_reports(self, evaluation_results: dict):
        """生成各种格式的报告"""
        report_formats = self.config.get('output', {}).get('formats', ['json', 'html'])
        
        # JSON报告（总是生成）
        json_path = self.output_dir / f"evaluation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_path, 'w') as f:
            json.dump(evaluation_results, f, indent=2, default=str)
        self.logger.info(f"JSON report saved: {json_path}")
        
        # HTML报告
        if 'html' in report_formats:
            html_path = self._generate_html_report(evaluation_results)
            self.logger.info(f"HTML report saved: {html_path}")
        
        # Markdown摘要
        if 'markdown' in report_formats:
            md_path = self._generate_markdown_summary(evaluation_results)
            self.logger.info(f"Markdown summary saved: {md_path}")
    
    def _generate_html_report(self, results: dict) -> Path:
        """生成HTML报告（简化版）"""
        html_path = self.output_dir / "evaluation_report.html"
        
        quality_score = results['results'].get('quality_scores', {}).get('overall', 0)
        grade = results['results'].get('quality_scores', {}).get('grade', 'N/A')
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>CyberRange Dataset Evaluation Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; }}
        .metric {{ margin: 10px 0; }}
        .score {{ font-size: 48px; font-weight: bold; color: #2ecc71; }}
        .grade {{ font-size: 36px; font-weight: bold; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>CyberRange Dataset Quality Evaluation Report</h1>
        <p>Generated: {results['timestamp']}</p>
    </div>
    
    <h2>Overall Quality Assessment</h2>
    <div class="metric">
        <span class="score">{quality_score:.1%}</span>
        <span class="grade">Grade: {grade}</span>
    </div>
    
    <h2>Quality Components</h2>
    <table>
        <tr>
            <th>Component</th>
            <th>Score</th>
        </tr>
"""
        
        # 添加质量组件分数
        components = results['results'].get('quality_scores', {}).get('components', {})
        for component, score in components.items():
            html_content += f"""
        <tr>
            <td>{component.replace('_', ' ').title()}</td>
            <td>{score:.3f}</td>
        </tr>
"""
        
        html_content += """
    </table>
    
    <h2>Dataset Statistics</h2>
"""
        
        # 添加数据集统计
        if 'cyberrange' in results['results']:
            stats = results['results']['cyberrange'].get('ground_truth', {}).get('summary', {})
            html_content += f"""
    <ul>
        <li>Total Events: {stats.get('total_records', 0):,}</li>
        <li>Attack Events: {stats.get('attack_records', 0):,}</li>
        <li>Benign Events: {stats.get('benign_records', 0):,}</li>
    </ul>
"""
        
        html_content += """
</body>
</html>
"""
        
        with open(html_path, 'w') as f:
            f.write(html_content)
        
        return html_path
    
    def _generate_markdown_summary(self, results: dict) -> Path:
        """生成Markdown摘要"""
        md_path = self.output_dir / "EVALUATION_SUMMARY.md"
        
        summary = self.dataset_evaluator.generate_summary()
        
        md_content = f"""# CyberRange Dataset Evaluation Summary

**Generated**: {results['timestamp']}  
**Dataset**: CyberRange

## 🎯 Overall Quality Assessment

**Quality Score**: {summary['quality_score']:.1%}  
**Grade**: **{summary['grade']}**

## 📊 Key Metrics

- Total Packets: {summary.get('total_packets', 0):,}
- Duration: {summary.get('duration_seconds', 0):.1f} seconds
- Total Events: {summary.get('total_events', 0):,}
- Attack Ratio: {summary.get('attack_ratio', 0):.1%}

## 🔍 Key Findings

"""
        
        for finding in summary.get('key_findings', []):
            md_content += f"- {finding}\n"
        
        # 添加质量组件详情
        components = results['results'].get('quality_scores', {}).get('components', {})
        if components:
            md_content += "\n## 📈 Quality Components\n\n"
            for component, score in components.items():
                md_content += f"- **{component.replace('_', ' ').title()}**: {score:.3f}\n"
        
        # 添加检测结果（如果有）
        if 'detection' in results['results'] and 'validation' in results['results']['detection']:
            md_content += "\n## 🛡️ IDS Detection Performance\n\n"
            validation = results['results']['detection']['validation']
            
            for detector, metrics in validation.items():
                if detector == 'best_detector':
                    continue
                if 'metrics' in metrics:
                    m = metrics['metrics']
                    md_content += f"### {detector.upper()}\n"
                    md_content += f"- Precision: {m.get('precision', 0):.1%}\n"
                    md_content += f"- Recall: {m.get('recall', 0):.1%}\n"
                    md_content += f"- F1-Score: {m.get('f1_score', 0):.1%}\n\n"
        
        # 添加建议
        recommendation = results['results'].get('quality_scores', {}).get('recommendation', '')
        if recommendation:
            md_content += f"\n## 💡 Recommendation\n\n{recommendation}\n"
        
        md_content += "\n---\n*CyberRange Dataset Quality Evaluation Tool*\n"
        
        with open(md_path, 'w') as f:
            f.write(md_content)
        
        return md_path
    
    def _save_results(self, results: dict):
        """保存完整的评估结果"""
        # 主结果文件
        main_result_file = self.dataset_evaluator.save_evaluation_results()
        self.logger.info(f"Main evaluation results saved: {main_result_file}")
        
        # IDS检测结果
        if 'detection' in results['results']:
            ids_result_file = self.ids_manager.save_detection_results(
                results['results']['detection']
            )
            self.logger.info(f"IDS detection results saved: {ids_result_file}")
    
    def _display_summary(self, results: dict):
        """显示评估摘要"""
        print("\n" + "="*60)
        print("📊 EVALUATION COMPLETE")
        print("="*60)
        
        quality_scores = results['results'].get('quality_scores', {})
        print(f"\n🎯 Overall Quality Score: {quality_scores.get('overall', 0):.1%}")
        print(f"📈 Grade: {quality_scores.get('grade', 'N/A')}")
        
        print("\n📊 Quality Components:")
        for component, score in quality_scores.get('components', {}).items():
            print(f"  • {component.replace('_', ' ').title()}: {score:.3f}")
        
        if 'detection' in results['results'] and 'validation' in results['results']['detection']:
            best = results['results']['detection']['validation'].get('best_detector', {})
            if best:
                print(f"\n🏆 Best IDS Detector: {best['name']} (F1: {best['f1_score']:.3f})")
        
        print(f"\n📁 Results saved to: {self.output_dir}")
        print("="*60)


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='Evaluate CyberRange dataset quality'
    )
    parser.add_argument(
        '--config',
        default='evaluation_config.yaml',
        help='Configuration file path (YAML or JSON)'
    )
    parser.add_argument(
        '--cyberrange-pcap',
        help='Override CyberRange PCAP path from config'
    )
    parser.add_argument(
        '--cyberrange-gt',
        help='Override CyberRange GT log path from config'
    )
    parser.add_argument(
        '--skip-baseline',
        action='store_true',
        help='Skip baseline generation/evaluation'
    )
    parser.add_argument(
        '--skip-ids',
        action='store_true',
        help='Skip IDS detection'
    )
    
    args = parser.parse_args()
    
    # 检查配置文件
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"❌ Configuration file not found: {args.config}")
        print("\n💡 Creating default configuration file...")
        
        # 创建默认配置
        default_config = {
            'evaluation': {
                'name': 'CyberRange Dataset Quality Evaluation'
            },
            'datasets': {
                'cyberrange': {
                    'pcap_path': args.cyberrange_pcap or '/path/to/cyberrange.pcap',
                    'gt_log_path': args.cyberrange_gt or '/path/to/nginx_detailed.csv'
                }
            },
            'baseline': {
                'generate_fiberfox': False,
                'target_url': 'http://localhost:3000',
                'duration': 60,
                'existing_pcaps': {
                    'SLOW': '/path/to/fiberfox_slow.pcap',
                    'GET': '/path/to/fiberfox_get.pcap',
                    'BYPASS': '/path/to/fiberfox_bypass.pcap',
                    'AVB': '/path/to/fiberfox_avb.pcap'
                }
            },
            'detection': {
                'enabled': True,
                'detectors': {
                    'suricata': True
                },
                'time_tolerance': 5.0
            },
            'output': {
                'directory': './evaluation_results',
                'formats': ['json', 'html', 'markdown']
            },
            'logging': {
                'level': 'INFO',
                'file': True
            }
        }
        
        with open('evaluation_config.yaml', 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
        
        print("✅ Created evaluation_config.yaml")
        print("📝 Please edit the configuration file and run again")
        return 1
    
    try:
        # 创建评估器
        evaluator = CyberRangeEvaluator(str(config_path))
        
        # 覆盖配置（如果提供了命令行参数）
        if args.cyberrange_pcap:
            evaluator.config['datasets']['cyberrange']['pcap_path'] = args.cyberrange_pcap
        if args.cyberrange_gt:
            evaluator.config['datasets']['cyberrange']['gt_log_path'] = args.cyberrange_gt
        if args.skip_baseline:
            evaluator.config['baseline']['generate_fiberfox'] = False
            evaluator.config['baseline']['existing_pcaps'] = {}
        if args.skip_ids:
            evaluator.config['detection']['enabled'] = False
        
        # 运行评估
        evaluator.run_evaluation()
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Evaluation failed: {e}")
        logging.exception("Evaluation failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
