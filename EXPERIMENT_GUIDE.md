# Security Logs 实验完整指南

## 概述
本指南涵盖了从环境构建到实验执行的完整流程，包括所有可能遇到的问题和解决方案。

## 1. 环境准备

### 1.1 系统要求
- Linux系统 (Ubuntu 20.04+)
- Docker 和 Docker Compose
- Python 3.8+
- 至少 4GB RAM
- 至少 10GB 可用磁盘空间

### 1.2 安装依赖
```bash
# 更新系统
sudo apt update && sudo apt upgrade -y

# 安装Docker
sudo apt install docker.io docker-compose -y
sudo usermod -aG docker $USER
newgrp docker

# 安装Python依赖
pip3 install pandas requests
```

### 1.3 克隆项目
```bash
git clone <repository_url>
cd SecurityLogs
```

## 2. 项目构建

### 2.1 构建Docker镜像
```bash
# 构建所有容器镜像
docker-compose -f scenarios/low-and-slow-sqli/docker-compose.yml build

# 验证镜像构建成功
docker images | grep securitylogs
```

### 2.2 检查项目结构
```bash
# 验证目录结构
ls -la scenarios/low-and-slow-sqli/
ls -la experiments/
ls -la data/
```

## 3. 实验执行流程

### 3.1 单个变体实验
```bash
# 运行单个变体
./experiments/run_variant.sh <variant_name> <duration>

# 示例
./experiments/run_variant.sh lowscan_stealthy moderate
./experiments/run_variant.sh lowscan_aggressive moderate
./experiments/run_variant.sh lowscan_moderate moderate
```

### 3.2 批量运行所有变体
```bash
# 运行所有变体
./experiments/run_all_variants.sh

# 或者手动运行
for variant in lowscan_stealthy lowscan_aggressive lowscan_moderate; do
    echo "Running variant: $variant"
    ./experiments/run_variant.sh $variant moderate
done
```

## 4. 常见问题和解决方案

### 4.1 权限问题

**问题**: 无法读取日志文件或创建目录
```
Permission denied: data/logs/
```

**解决方案**:
```bash
# 修复权限
sudo chown -R $USER:$USER data/
chmod -R 755 data/
```

### 4.2 路径问题

**问题**: 脚本找不到文件
```
File not found: etl_scripts/etl_container_logs.py
```

**解决方案**:
```bash
# 确保在项目根目录执行
cd /home/jiayi/SecurityLogs

# 检查脚本路径
ls -la experiments/etl_scripts/
```

### 4.3 容器启动失败

**问题**: Docker容器无法启动
```
Error: failed to start container
```

**解决方案**:
```bash
# 清理Docker资源
docker system prune -f
docker volume prune -f

# 重新构建镜像
docker-compose -f scenarios/low-and-slow-sqli/docker-compose.yml down
docker-compose -f scenarios/low-and-slow-sqli/docker-compose.yml build --no-cache
```

### 4.4 网络问题

**问题**: 容器间无法通信
```
Connection refused: victim-web:80
```

**解决方案**:
```bash
# 检查网络配置
docker network ls
docker network inspect lowscan_stealthy_net

# 重启网络
docker network prune -f
```

### 4.5 ETL脚本错误

**问题**: ETL处理失败
```
ModuleNotFoundError: No module named 'pandas'
```

**解决方案**:
```bash
# 安装Python依赖
pip3 install pandas requests

# 检查Python路径
which python3
python3 -c "import pandas; print('pandas installed')"
```

### 4.6 日志收集失败

**问题**: 无法收集容器日志
```
No logs found for container
```

**解决方案**:
```bash
# 检查容器状态
docker ps -a

# 手动收集日志
docker logs <container_name> > data/logs/<variant>/container_logs.txt
```

### 4.7 主机日志收集失败

**问题**: netstat命令不存在
```
No such file or directory: 'netstat'
```

**解决方案**:
```bash
# 安装net-tools
sudo apt install net-tools -y

# 或者使用ss命令替代
ss -tuln
```

### 4.8 数据集合并错误

**问题**: 攻击记录为0
```
Attack records: 0
```

**解决方案**:
```bash
# 检查攻击日志文件
ls -la data/logs/*/output/

# 手动运行合并脚本
python3 data/merge_variant_logs.py data/logs/lowscan_stealthy data/datasets/test.jsonl
```

## 5. 数据验证

### 5.1 检查日志文件
```bash
# 检查各类型日志
ls -la data/logs/lowscan_stealthy/
wc -l data/logs/lowscan_stealthy/nginx/access.log
wc -l data/logs/lowscan_stealthy/host/syslog
```

### 5.2 验证攻击记录
```bash
# 检查攻击日志
cat data/logs/lowscan_stealthy/output/container_attack_log.json

# 检查数据集中的攻击记录
grep -E '"source_type": "attack"' data/datasets/lowscan_stealthy_dataset.jsonl | wc -l
```

### 5.3 验证数据集统计
```bash
# 查看数据集统计
cat data/datasets/lowscan_stealthy_dataset_stats.json
```

## 6. 清理和维护

### 6.1 清理实验数据
```bash
# 清理所有变体数据
rm -rf data/logs/*
rm -rf data/datasets/*

# 清理Docker资源
docker-compose -f scenarios/low-and-slow-sqli/docker-compose.yml down
docker system prune -f
```

### 6.2 备份重要数据
```bash
# 备份数据集
tar -czf datasets_backup_$(date +%Y%m%d).tar.gz data/datasets/

# 备份日志
tar -czf logs_backup_$(date +%Y%m%d).tar.gz data/logs/
```

## 7. 故障排除检查清单

### 7.1 环境检查
- [ ] Docker服务运行正常
- [ ] Python 3.8+已安装
- [ ] 项目目录权限正确
- [ ] 网络连接正常

### 7.2 脚本检查
- [ ] 所有脚本有执行权限
- [ ] 路径配置正确
- [ ] 依赖包已安装

### 7.3 容器检查
- [ ] 镜像构建成功
- [ ] 容器能正常启动
- [ ] 容器间网络连通

### 7.4 日志检查
- [ ] 日志目录存在
- [ ] 日志文件有内容
- [ ] 权限设置正确

### 7.5 数据处理检查
- [ ] ETL脚本运行成功
- [ ] 数据集文件生成
- [ ] 攻击记录正确标记

## 8. 性能优化建议

### 8.1 系统优化
```bash
# 增加Docker内存限制
echo '{"default-shm-size": "2G"}' | sudo tee /etc/docker/daemon.json
sudo systemctl restart docker
```

### 8.2 存储优化
```bash
# 使用SSD存储
# 定期清理日志文件
find data/logs/ -name "*.log" -mtime +7 -delete
```

## 9. 联系支持

如果遇到未解决的问题：
1. 检查系统日志: `journalctl -xe`
2. 检查Docker日志: `docker logs <container_name>`
3. 查看实验脚本输出
4. 收集错误信息和环境信息

---

**注意**: 本指南基于当前项目版本，如有更新请参考最新文档。 