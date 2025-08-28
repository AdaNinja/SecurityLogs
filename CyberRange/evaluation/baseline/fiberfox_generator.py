#!/usr/bin/env python3
"""
Fiberfox PCAP Generator Integration
用于生成基准PCAP文件，作为评估CyberRange数据集质量的参考
"""

import os
import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Optional
import shutil
import time
import json
from datetime import datetime


class FiberfoxGenerator:
    """Fiberfox PCAP生成器"""
    
    # 支持的攻击策略
    STRATEGIES = ["SLOW", "GET", "BYPASS", "AVB"]
    
    def __init__(self, fiberfox_path: str = None, output_dir: str = "./baseline_pcaps"):
        """
        初始化Fiberfox生成器
        
        Args:
            fiberfox_path: Fiberfox工具路径，默认使用analysis目录下的
            output_dir: 输出目录
        """
        self.logger = logging.getLogger(__name__)
        
        # 设置Fiberfox路径
        if fiberfox_path:
            self.fiberfox_path = Path(fiberfox_path)
        else:
            # 默认使用analysis目录下的fiberfox
            self.fiberfox_path = Path(__file__).parent.parent.parent / "analysis/data_sources/fiberfox_data/fiberfox_pcaps/fiberfox"
        
        if not self.fiberfox_path.exists():
            raise FileNotFoundError(f"Fiberfox not found at: {self.fiberfox_path}")
        
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # 检查必要的脚本
        self.single_script = self.fiberfox_path / "run_single_strategy.sh"
        self.batch_script = self.fiberfox_path / "run_all_strategies.sh"
        
        self.logger.info(f"Fiberfox generator initialized with path: {self.fiberfox_path}")
    
    def generate_single_pcap(self, target_url: str, strategy: str, 
                           duration: int = 60, max_size_mb: int = 50) -> Optional[Path]:
        """
        生成单个策略的PCAP文件
        
        Args:
            target_url: 目标URL
            strategy: 攻击策略 (SLOW, GET, BYPASS, AVB)
            duration: 持续时间（秒）
            max_size_mb: 最大文件大小（MB）
            
        Returns:
            生成的PCAP文件路径，失败返回None
        """
        if strategy not in self.STRATEGIES:
            raise ValueError(f"Invalid strategy: {strategy}. Must be one of {self.STRATEGIES}")
        
        self.logger.info(f"Generating {strategy} PCAP for target: {target_url}")
        
        # 检查脚本是否存在
        if not self.single_script.exists():
            self.logger.error(f"Script not found: {self.single_script}")
            return None
        
        # 确保脚本有执行权限
        os.chmod(self.single_script, 0o755)
        
        # 准备输出文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_filename = f"fiberfox_{strategy.lower()}_{timestamp}.pcap"
        
        try:
            # 切换到fiberfox目录执行
            original_dir = os.getcwd()
            os.chdir(self.fiberfox_path)
            
            # 执行生成命令
            cmd = [
                str(self.single_script),
                target_url,
                strategy,
                str(duration),
                str(max_size_mb)
            ]
            
            self.logger.debug(f"Executing command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=duration + 30  # 给额外30秒的缓冲时间
            )
            
            if result.returncode != 0:
                self.logger.error(f"Fiberfox generation failed: {result.stderr}")
                return None
            
            # 查找生成的PCAP文件
            expected_pcap = self.fiberfox_path / "pcaps" / f"fiberfox_{strategy.lower()}.pcap"
            
            if expected_pcap.exists():
                # 复制到输出目录
                output_path = self.output_dir / output_filename
                shutil.copy2(expected_pcap, output_path)
                
                # 检查文件大小
                file_size_mb = output_path.stat().st_size / (1024 * 1024)
                self.logger.info(f"Generated PCAP: {output_path} ({file_size_mb:.2f} MB)")
                
                if file_size_mb > max_size_mb:
                    self.logger.warning(f"File size ({file_size_mb:.2f} MB) exceeds limit ({max_size_mb} MB)")
                
                return output_path
            else:
                self.logger.error(f"Expected PCAP not found: {expected_pcap}")
                return None
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Fiberfox generation timed out after {duration + 30} seconds")
            return None
        except Exception as e:
            self.logger.error(f"Error generating PCAP: {e}")
            return None
        finally:
            os.chdir(original_dir)
    
    def generate_all_pcaps(self, target_url: str, duration: int = 60) -> Dict[str, Path]:
        """
        生成所有策略的PCAP文件
        
        Args:
            target_url: 目标URL
            duration: 每个策略的持续时间
            
        Returns:
            策略名到PCAP文件路径的映射
        """
        self.logger.info(f"Generating all strategy PCAPs for target: {target_url}")
        
        results = {}
        
        for strategy in self.STRATEGIES:
            pcap_path = self.generate_single_pcap(target_url, strategy, duration)
            if pcap_path:
                results[strategy] = pcap_path
                # 在策略之间稍作休息
                time.sleep(3)
            else:
                self.logger.warning(f"Failed to generate {strategy} PCAP")
        
        # 生成元数据文件
        self._save_metadata(results, target_url, duration)
        
        return results
    
    def _save_metadata(self, results: Dict[str, Path], target_url: str, duration: int):
        """保存生成的PCAP元数据"""
        metadata = {
            "generation_time": datetime.now().isoformat(),
            "target_url": target_url,
            "duration": duration,
            "strategies": {}
        }
        
        for strategy, pcap_path in results.items():
            if pcap_path.exists():
                metadata["strategies"][strategy] = {
                    "file": str(pcap_path),
                    "size_mb": pcap_path.stat().st_size / (1024 * 1024),
                    "generated": True
                }
            else:
                metadata["strategies"][strategy] = {
                    "generated": False
                }
        
        metadata_path = self.output_dir / "fiberfox_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        self.logger.info(f"Metadata saved to: {metadata_path}")
    
    def verify_fiberfox_installation(self) -> bool:
        """验证Fiberfox是否正确安装和配置"""
        checks = {
            "fiberfox_dir": self.fiberfox_path.exists(),
            "main_script": (self.fiberfox_path / "fiberfox" / "main.py").exists(),
            "single_script": self.single_script.exists(),
            "batch_script": self.batch_script.exists(),
            "pcaps_dir": (self.fiberfox_path / "pcaps").exists()
        }
        
        all_passed = all(checks.values())
        
        if not all_passed:
            self.logger.error("Fiberfox verification failed:")
            for check, passed in checks.items():
                if not passed:
                    self.logger.error(f"  ❌ {check}")
        else:
            self.logger.info("✅ Fiberfox verification passed")
        
        return all_passed
    
    def cleanup_old_pcaps(self, keep_latest: int = 5):
        """清理旧的PCAP文件，保留最新的N个"""
        pcap_files = list(self.output_dir.glob("fiberfox_*.pcap"))
        
        if len(pcap_files) <= keep_latest:
            return
        
        # 按修改时间排序
        pcap_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        
        # 删除旧文件
        for pcap_file in pcap_files[keep_latest:]:
            pcap_file.unlink()
            self.logger.info(f"Removed old PCAP: {pcap_file}")


def main():
    """测试Fiberfox生成器"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate Fiberfox baseline PCAPs")
    parser.add_argument("target", help="Target URL (e.g., http://localhost:3000)")
    parser.add_argument("--strategy", choices=FiberfoxGenerator.STRATEGIES,
                       help="Specific strategy to generate (default: all)")
    parser.add_argument("--duration", type=int, default=60,
                       help="Duration in seconds (default: 60)")
    parser.add_argument("--output", default="./baseline_pcaps",
                       help="Output directory (default: ./baseline_pcaps)")
    
    args = parser.parse_args()
    
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 创建生成器
    generator = FiberfoxGenerator(output_dir=args.output)
    
    # 验证安装
    if not generator.verify_fiberfox_installation():
        return 1
    
    # 生成PCAP
    if args.strategy:
        # 生成单个策略
        pcap_path = generator.generate_single_pcap(args.target, args.strategy, args.duration)
        if pcap_path:
            print(f"✅ Generated: {pcap_path}")
            return 0
        else:
            print(f"❌ Failed to generate {args.strategy} PCAP")
            return 1
    else:
        # 生成所有策略
        results = generator.generate_all_pcaps(args.target, args.duration)
        
        print("\n📊 Generation Summary:")
        for strategy, pcap_path in results.items():
            if pcap_path and pcap_path.exists():
                size_mb = pcap_path.stat().st_size / (1024 * 1024)
                print(f"  ✅ {strategy}: {pcap_path.name} ({size_mb:.2f} MB)")
            else:
                print(f"  ❌ {strategy}: Failed")
        
        return 0 if results else 1


if __name__ == "__main__":
    exit(main())
