#!/usr/bin/env python3
"""
攻击场景启动脚本
"""

import os
import sys
import subprocess
import time
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def check_dependencies():
    """检查依赖"""
    logger.info("检查依赖...")
    
    # 检查Docker
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            logger.info("✓ Docker 已安装")
        else:
            logger.error("✗ Docker 未安装或不可用")
            return False
    except FileNotFoundError:
        logger.error("✗ Docker 未安装")
        return False
    
    # 检查Docker Compose
    try:
        result = subprocess.run(["docker-compose", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            logger.info("✓ Docker Compose 已安装")
        else:
            logger.error("✗ Docker Compose 未安装或不可用")
            return False
    except FileNotFoundError:
        logger.error("✗ Docker Compose 未安装")
        return False
    
    return True

def build_containers():
    """构建容器"""
    logger.info("构建Docker容器...")
    
    try:
        result = subprocess.run(
            ["docker-compose", "-f", "docker/docker-compose.yml", "build"],
            cwd=".",
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            logger.info("✓ 容器构建成功")
            return True
        else:
            logger.error(f"✗ 容器构建失败: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"✗ 构建容器时出错: {e}")
        return False

def start_containers():
    """启动容器"""
    logger.info("启动Docker容器...")
    
    try:
        result = subprocess.run(
            ["docker-compose", "-f", "docker/docker-compose.yml", "up", "-d"],
            cwd=".",
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            logger.info("✓ 容器启动成功")
            return True
        else:
            logger.error(f"✗ 容器启动失败: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"✗ 启动容器时出错: {e}")
        return False

def wait_for_services():
    """等待服务就绪"""
    logger.info("等待服务就绪...")
    
    import requests
    
    services = [
        ("MailHog Web UI", "http://localhost:8025"),
        ("凭证收集服务器", "http://localhost:9000/health")
    ]
    
    for service_name, url in services:
        logger.info(f"检查 {service_name}...")
        for i in range(30):  # 最多等待30秒
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    logger.info(f"✓ {service_name} 就绪")
                    break
            except:
                if i == 29:
                    logger.warning(f"⚠ {service_name} 可能未就绪，但继续执行")
                else:
                    time.sleep(1)

def run_scenario():
    """运行攻击场景"""
    logger.info("运行钓鱼攻击场景...")
    
    try:
        result = subprocess.run(
            [sys.executable, "run_scenario.py", "--config", "scenarios/phishing/scenario.yaml"],
            cwd=".",
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            logger.info("✓ 攻击场景执行成功")
            logger.info("输出:")
            print(result.stdout)
        else:
            logger.error(f"✗ 攻击场景执行失败: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"✗ 运行场景时出错: {e}")
        return False
    
    return True

def show_results():
    """显示结果"""
    logger.info("=== 攻击结果 ===")
    
    # 检查凭证收集
    try:
        import requests
        response = requests.get("http://localhost:9000/credentials", timeout=5)
        if response.status_code == 200:
            data = response.json()
            logger.info(f"收集到的凭证数量: {data.get('count', 0)}")
            if data.get('credentials'):
                logger.info("凭证详情:")
                for cred in data['credentials']:
                    logger.info(f"  - 时间: {cred.get('timestamp')}")
                    logger.info(f"    IP: {cred.get('ip')}")
                    logger.info(f"    凭证: {cred.get('credentials')}")
        else:
            logger.warning("无法获取凭证收集结果")
    except Exception as e:
        logger.warning(f"检查结果时出错: {e}")

def main():
    """主函数"""
    logger.info("=== 钓鱼攻击场景启动器 ===")
    
    # 1. 检查依赖
    if not check_dependencies():
        logger.error("依赖检查失败，请安装必要的工具")
        return
    
    # 2. 构建容器
    if not build_containers():
        logger.error("容器构建失败")
        return
    
    # 3. 启动容器
    if not start_containers():
        logger.error("容器启动失败")
        return
    
    # 4. 等待服务就绪
    wait_for_services()
    
    # 5. 运行攻击场景
    if not run_scenario():
        logger.error("攻击场景执行失败")
        return
    
    # 6. 显示结果
    show_results()
    
    logger.info("=== 攻击场景完成 ===")
    logger.info("提示:")
    logger.info("- 查看MailHog邮件: http://localhost:8025")
    logger.info("- 查看凭证收集: http://localhost:9000/credentials")
    logger.info("- 停止容器: docker-compose -f docker/docker-compose.yml down")

if __name__ == "__main__":
    main() 