#!/usr/bin/env python3
"""
Enhanced Ground Truth Label Generator
增强Ground Truth标签生成工具
"""

import argparse
import json
import sys
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from evaluation.core.enhanced_gt_labeler import EnhancedGTLabeler

def main():
    parser = argparse.ArgumentParser(
        description='Generate enhanced Ground Truth labels with MITRE ATT&CK mapping'
    )
    
    parser.add_argument(
        'input_file',
        help='Path to nginx detailed CSV file'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file path (optional)',
        default=None
    )
    
    parser.add_argument(
        '-w', '--time-window',
        type=int,
        default=300,
        help='Time window for attack chain detection (seconds, default: 300)'
    )
    
    parser.add_argument(
        '-r', '--report',
        action='store_true',
        help='Generate detailed labeling report'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    # 检查输入文件
    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"错误: 输入文件不存在: {input_path}")
        sys.exit(1)
    
    # 确定输出文件路径
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = input_path.parent / "enhanced_labels.csv"
    
    print("=== 增强Ground Truth标签生成器 ===")
    print(f"输入文件: {input_path}")
    print(f"输出文件: {output_path}")
    print(f"时间窗口: {args.time_window}秒")
    print()
    
    try:
        # 创建标签生成器
        labeler = EnhancedGTLabeler(time_window=args.time_window)
        
        # 处理日志文件
        print("开始处理日志文件...")
        labels = labeler.process_nginx_logs(str(input_path), str(output_path))
        
        if not labels:
            print("警告: 没有生成任何标签")
            sys.exit(1)
        
        # 生成报告
        if args.report or args.verbose:
            print("\n生成标签统计报告...")
            report = labeler.generate_labeling_report(labels)
            
            print("\n=== 标签生成报告 ===")
            print(f"总事件数: {report['summary']['total_events']}")
            print(f"攻击事件: {report['summary']['attack_events']}")
            print(f"良性事件: {report['summary']['benign_events']}")
            print(f"攻击率: {report['summary']['attack_rate']:.2%}")
            
            print(f"\n检测到的攻击技术 (前5个):")
            for technique, count in list(report['attack_techniques'].items())[:5]:
                print(f"  {technique}: {count}")
            
            print(f"\n检测到的攻击战术:")
            for tactic, count in report['attack_tactics'].items():
                print(f"  {tactic}: {count}")
            
            print(f"\n严重性分布:")
            for severity, count in report['severity_distribution'].items():
                print(f"  {severity}: {count}")
            
            print(f"\n攻击链统计:")
            print(f"  总攻击链数: {report['attack_chains']['total_chains']}")
            print(f"  多步骤攻击: {report['attack_chains']['multi_step_attacks']}")
            
            print(f"\n异常分数统计:")
            print(f"  平均分数: {report['anomaly_scores']['mean']:.3f}")
            print(f"  最高分数: {report['anomaly_scores']['max']:.3f}")
            print(f"  高异常事件: {report['anomaly_scores']['high_anomaly_count']}")
            
            # 保存详细报告
            if args.report:
                report_file = output_path.parent / "labeling_report.json"
                with open(report_file, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                print(f"\n详细报告已保存: {report_file}")
        
        print(f"\n✅ 成功生成 {len(labels)} 个增强标签")
        print(f"结果已保存到: {output_path.parent}")
        
    except Exception as e:
        print(f"错误: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
