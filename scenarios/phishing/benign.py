#!/usr/bin/env python3
"""
良性行为脚本 - 模拟正常的网络活动
"""

import time
import requests
import random
import logging
from logger_utils import log_attack_event

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run(params):
    """
    执行良性网络活动
    
    Args:
        params: 场景参数字典
    """
    logger.info("开始执行良性网络活动...")
    
    benign_sites = params.get("benign_sites", [
        "http://example.com",
        "http://example.org",
        "http://httpbin.org"
    ])
    
    # 模拟正常的网络浏览行为
    for i in range(5):
        try:
            # 随机选择一个网站
            site = random.choice(benign_sites)
            logger.info(f"访问网站: {site}")
            
            # 发送HTTP请求
            response = requests.get(site, timeout=10)
            logger.info(f"响应状态码: {response.status_code}")
            
            # 记录良性活动
            log_attack_event("benign_web_access", {
                "site": site,
                "status_code": response.status_code,
                "iteration": i + 1
            })
            
            # 随机延迟
            delay = random.uniform(2, 8)
            logger.info(f"等待 {delay:.1f} 秒...")
            time.sleep(delay)
            
        except requests.RequestException as e:
            logger.warning(f"访问 {site} 失败: {e}")
            log_attack_event("benign_access_failed", {
                "site": site,
                "error": str(e)
            })
        except Exception as e:
            logger.error(f"良性活动执行出错: {e}")
    
    logger.info("良性网络活动完成")
    log_attack_event("benign_activity_complete", {"total_requests": 5})
