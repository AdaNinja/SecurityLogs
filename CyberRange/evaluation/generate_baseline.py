#!/usr/bin/env python3
"""
Generate Baseline PCAP Files
生成Fiberfox基准PCAP文件的独立脚本
"""

import argparse
import logging
import sys
from pathlib import Path

# 添加模块路径
sys.path.append(str(Path(__file__).parent.parent))

from evaluation.baseline.fiberfox_generator import FiberfoxGenerator
from evaluation.baseline.fiberfox_configs import FiberfoxConfig


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='Generate Fiberfox baseline PCAP files for evaluation'
    )
    parser.add_argument(
        'target',
        help='Target URL (e.g., http://localhost:3000)'
    )
    parser.add_argument(
        '--strategy',
        choices=['SLOW', 'GET', 'BYPASS', 'AVB'],
        help='Specific strategy to generate (default: all)'
    )
    parser.add_argument(
        '--duration',
        type=int,
        default=60,
        help='Duration in seconds (default: 60)'
    )
    parser.add_argument(
        '--output',
        default='./baseline_pcaps',
        help='Output directory (default: ./baseline_pcaps)'
    )
    parser.add_argument(
        '--max-size',
        type=int,
        default=50,
        help='Max file size in MB (default: 50)'
    )
    parser.add_argument(
        '--verify-only',
        action='store_true',
        help='Only verify Fiberfox installation'
    )
    
    args = parser.parse_args()
    
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 创建生成器
    generator = FiberfoxGenerator(output_dir=args.output)
    
    # 验证安装
    print("\n🔍 Verifying Fiberfox installation...")
    if not generator.verify_fiberfox_installation():
        print("❌ Fiberfox verification failed!")
        print("\n💡 Please ensure Fiberfox is properly installed:")
        print("   1. Check if Fiberfox directory exists")
        print("   2. Verify all required scripts are present")
        print("   3. Ensure Python dependencies are installed")
        return 1
    
    print("✅ Fiberfox verification passed!")
    
    if args.verify_only:
        return 0
    
    # 验证目标URL
    if not FiberfoxConfig.validate_target(args.target):
        print(f"❌ Invalid target URL: {args.target}")
        print("💡 URL must start with http:// or https://")
        return 1
    
    print(f"\n🎯 Target: {args.target}")
    
    # 生成PCAP
    if args.strategy:
        # 生成单个策略
        print(f"\n🚀 Generating {args.strategy} baseline...")
        print(f"📊 Strategy: {FiberfoxConfig.get_strategy_description(args.strategy)}")
        
        # 使用推荐的持续时间（如果用户没有指定）
        duration = args.duration
        if duration == 60:  # 默认值
            duration = FiberfoxConfig.get_recommended_duration(args.strategy)
            print(f"⏱️  Using recommended duration: {duration}s")
        
        # 估算文件大小
        estimated_size = FiberfoxConfig.get_pcap_size_estimate(args.strategy, duration)
        print(f"💾 Estimated file size: {estimated_size:.1f} MB")
        
        if estimated_size > args.max_size:
            print(f"⚠️  Warning: Estimated size exceeds limit ({args.max_size} MB)")
            print("💡 Consider reducing duration or increasing max-size")
        
        # 生成PCAP
        pcap_path = generator.generate_single_pcap(
            args.target,
            args.strategy,
            duration,
            args.max_size
        )
        
        if pcap_path and pcap_path.exists():
            actual_size = pcap_path.stat().st_size / (1024 * 1024)
            print(f"\n✅ Successfully generated: {pcap_path}")
            print(f"📊 Actual file size: {actual_size:.2f} MB")
            
            # 显示攻击特征
            characteristics = FiberfoxConfig.get_attack_characteristics(args.strategy)
            if characteristics:
                print(f"\n🔍 Expected characteristics:")
                print(f"   Traffic pattern: {characteristics.get('traffic_pattern', 'N/A')}")
                print(f"   Expected alerts: {', '.join(characteristics.get('expected_alerts', []))}")
            
            return 0
        else:
            print(f"\n❌ Failed to generate {args.strategy} PCAP")
            return 1
    
    else:
        # 生成所有策略
        print("\n🚀 Generating all baseline strategies...")
        print("📋 Strategies to generate:")
        for strategy in FiberfoxGenerator.STRATEGIES:
            desc = FiberfoxConfig.get_strategy_description(strategy)
            duration_rec = FiberfoxConfig.get_recommended_duration(strategy)
            print(f"   • {strategy}: {desc} (recommended: {duration_rec}s)")
        
        print(f"\n⏱️  Duration for each: {args.duration}s")
        print(f"💾 Max size per file: {args.max_size} MB")
        
        # 确认继续
        total_estimated_size = sum(
            FiberfoxConfig.get_pcap_size_estimate(s, args.duration)
            for s in FiberfoxGenerator.STRATEGIES
        )
        print(f"\n📊 Total estimated size: {total_estimated_size:.1f} MB")
        
        input("\nPress Enter to continue or Ctrl+C to cancel...")
        
        # 生成所有PCAP
        results = generator.generate_all_pcaps(args.target, args.duration)
        
        # 显示结果
        print("\n" + "="*60)
        print("📊 GENERATION SUMMARY")
        print("="*60)
        
        success_count = 0
        total_size = 0
        
        for strategy in FiberfoxGenerator.STRATEGIES:
            if strategy in results and results[strategy].exists():
                pcap_path = results[strategy]
                size_mb = pcap_path.stat().st_size / (1024 * 1024)
                total_size += size_mb
                success_count += 1
                print(f"✅ {strategy}: {pcap_path.name} ({size_mb:.2f} MB)")
            else:
                print(f"❌ {strategy}: Failed")
        
        print(f"\n📊 Total: {success_count}/{len(FiberfoxGenerator.STRATEGIES)} successful")
        print(f"💾 Total size: {total_size:.2f} MB")
        print(f"📁 Output directory: {generator.output_dir}")
        
        # 显示如何使用生成的文件
        if success_count > 0:
            print("\n💡 Next steps:")
            print("1. Use these baseline PCAPs in your evaluation config")
            print("2. Run: python evaluate.py --config your_config.yaml")
            print("\n📝 Example config snippet:")
            print("baseline:")
            print("  existing_pcaps:")
            for strategy, pcap_path in results.items():
                if pcap_path.exists():
                    print(f"    {strategy}: '{pcap_path}'")
        
        return 0 if success_count > 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Generation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        logging.exception("Generation failed")
        sys.exit(1)
