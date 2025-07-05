#!/usr/bin/env python3
"""
日志工具模块 - 提供日志打标和延迟功能
"""

import subprocess
import time
import logging
from typing import Optional

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def inject_label(label: str):
    """
    注入攻击阶段标签到系统日志
    
    Args:
        label: 标签字符串，格式如 "phase=Reconnaissance"
    """
    try:
        result = subprocess.run(
            ["logger", "-t", "APT", label],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            logger.info(f"成功注入标签: {label}")
        else:
            logger.error(f"注入标签失败: {result.stderr}")
    except subprocess.TimeoutExpired:
        logger.error("注入标签超时")
    except Exception as e:
        logger.error(f"注入标签时出错: {e}")

def sleep(sec: int):
    """
    延迟执行
    
    Args:
        sec: 延迟秒数
    """
    logger.info(f"延迟 {sec} 秒...")
    time.sleep(sec)
    logger.info("延迟完成")

def log_attack_event(event_type: str, details: Optional[dict] = None):
    """
    记录攻击事件
    
    Args:
        event_type: 事件类型
        details: 事件详情
    """
    event_data = {
        'event_type': event_type,
        'timestamp': time.time(),
        'details': details or {}
    }
    
    label = f"attack_event={event_type}"
    if details:
        for key, value in details.items():
            label += f" {key}={value}"
    
    inject_label(label)
    logger.info(f"记录攻击事件: {event_type} - {details}")
