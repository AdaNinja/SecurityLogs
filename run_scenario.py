#!/usr/bin/env python3
"""
场景调度入口 - 执行攻击场景的主控制器
"""

import argparse
import yaml
import importlib
import logging
from logger_utils import inject_label, sleep, log_attack_event

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='执行攻击场景')
    parser.add_argument("--config", required=True, help="场景配置文件路径")
    parser.add_argument("--dry-run", action="store_true", help="仅显示配置，不执行")
    args = parser.parse_args()
    
    try:
        # 加载配置文件
        logger.info(f"加载配置文件: {args.config}")
        with open(args.config, 'r', encoding='utf-8') as f:
            cfg = yaml.safe_load(f)
        
        if args.dry_run:
            logger.info("DRY RUN 模式 - 配置内容:")
            logger.info(yaml.dump(cfg, default_flow_style=False))
            return
        
        logger.info(f"开始执行场景: {cfg['name']}")
        
        # 1. Reconnaissance 阶段
        logger.info("=== 阶段 1: Reconnaissance ===")
        inject_label("phase=Reconnaissance")
        log_attack_event("reconnaissance_start", {"scenario": cfg['name']})
        
        try:
            benign_module = importlib.import_module(f"scenarios.{cfg['name']}.benign")
            benign_module.run(cfg["parameters"])
            log_attack_event("reconnaissance_complete")
        except Exception as e:
            logger.error(f"Reconnaissance 阶段失败: {e}")
            log_attack_event("reconnaissance_failed", {"error": str(e)})
            return
        
        # 2. 延迟
        delay_seconds = cfg["parameters"].get("attack_delay_s", 30)
        logger.info(f"=== 延迟 {delay_seconds} 秒 ===")
        sleep(delay_seconds)
        
        # 3. Delivery 阶段
        logger.info("=== 阶段 2: Delivery ===")
        inject_label("phase=Delivery")
        log_attack_event("delivery_start")
        
        try:
            attack_module = importlib.import_module(f"scenarios.{cfg['name']}.attack")
            attack_module.run(cfg["parameters"])
            log_attack_event("delivery_complete")
        except Exception as e:
            logger.error(f"Delivery 阶段失败: {e}")
            log_attack_event("delivery_failed", {"error": str(e)})
            return
        
        # 4. Exploitation 阶段
        logger.info("=== 阶段 3: Exploitation ===")
        inject_label("phase=Exploitation")
        log_attack_event("exploitation_start")
        
        # 这里可以添加额外的利用逻辑
        sleep(5)  # 模拟利用过程
        log_attack_event("exploitation_complete")
        
        logger.info("=== 场景执行完成 ===")
        inject_label("phase=Complete")
        log_attack_event("scenario_complete", {"scenario": cfg['name']})
        
    except FileNotFoundError:
        logger.error(f"配置文件不存在: {args.config}")
    except yaml.YAMLError as e:
        logger.error(f"配置文件格式错误: {e}")
    except Exception as e:
        logger.error(f"执行场景时出错: {e}")
        log_attack_event("scenario_failed", {"error": str(e)})

if __name__ == "__main__":
    main()
