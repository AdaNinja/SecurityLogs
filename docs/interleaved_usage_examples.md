# SecurityLogs 交错流量功能使用指南

## 概述

SecurityLogs的交错流量功能允许您在攻击执行期间同时运行良性流量，模拟真实的网络环境。这个功能已经集成到现有的变体实验系统中，无需单独选择。

## 快速开始

### 1. 基础使用

#### 运行单个变体（纯攻击）
```bash
# 使用Python脚本
python3 scripts/run_variant.py stealthy

# 使用Makefile
make run-variant VARIANT=stealthy
```

#### 运行单个变体（带交错流量）
```bash
# 使用Python脚本（推荐）
python3 scripts/run_variant.py stealthy --interleaved

# 使用Makefile
make run-variant-interleaved VARIANT=stealthy
```

### 2. 自定义配置

#### 自定义良性流量持续时间
```bash
# 60秒（快速测试）
python3 scripts/run_variant.py stealthy --interleaved --benign-duration 60

# 10分钟（长时间实验）
python3 scripts/run_variant.py stealthy --interleaved --benign-duration 600
```

#### 自定义协议混合比例
```bash
# 主要HTTP流量
python3 scripts/run_variant.py stealthy --interleaved --benign-mix "HTTP:0.8,DNS:0.2"

# 平衡配置
python3 scripts/run_variant.py stealthy --interleaved --benign-mix "HTTP:0.5,DNS:0.3,SMTP:0.2"

# 高HTTP比例
python3 scripts/run_variant.py stealthy --interleaved --benign-mix "HTTP:0.7,DNS:0.2,SMTP:0.1"
```

### 3. 批量运行

#### 运行所有变体（纯攻击）
```bash
# 使用Python脚本
python3 scripts/run_all_variants.py

# 使用Makefile
make run-all-variants
```

#### 运行所有变体（带交错流量）
```bash
# 使用Python脚本
python3 scripts/run_all_variants.py --interleaved

# 使用Makefile
make run-all-interleaved
```

#### 运行指定变体（带交错流量）
```bash
# 使用Python脚本
python3 scripts/run_all_variants.py --variants stealthy moderate --interleaved

# 使用Makefile
make run-variants-interleaved VARIANTS='stealthy moderate'
```

### 4. Makefile参数化使用

#### 使用环境变量
```bash
# 设置交错模式
export INTERLEAVED=true
export BENIGN_DURATION=300
export BENIGN_MIX="HTTP:0.7,DNS:0.2,SMTP:0.1"

# 运行
make run-variant VARIANT=stealthy
make run-all-variants
```

#### 直接传递参数
```bash
# 单个变体
make run-variant VARIANT=stealthy INTERLEAVED=true BENIGN_DURATION=300

# 所有变体
make run-all-variants INTERLEAVED=true BENIGN_MIX="HTTP:0.8,DNS:0.2"
```

## 高级配置

### 1. 协议混合详解

#### 支持的协议
- **HTTP**: Web流量模拟
- **DNS**: DNS查询模拟
- **SMTP**: 邮件流量模拟

#### 配置格式
```
协议名:比例,协议名:比例,...
```

#### 配置示例
```bash
# 默认配置
HTTP:0.6,DNS:0.3,SMTP:0.1

# Web应用环境
HTTP:0.8,DNS:0.2

# 邮件服务器环境
HTTP:0.3,DNS:0.2,SMTP:0.5

# 纯Web环境
HTTP:1.0
```

### 2. 持续时间配置

#### 推荐配置
```bash
# 快速测试（1-2分钟）
--benign-duration 60

# 标准实验（5-10分钟）
--benign-duration 300

# 长时间实验（15-30分钟）
--benign-duration 900

# 扩展实验（1小时以上）
--benign-duration 3600
```

### 3. 实验场景配置

#### 场景1：快速功能验证
```bash
# 60秒快速测试
python3 scripts/run_variant.py stealthy --interleaved --benign-duration 60
```

#### 场景2：标准安全测试
```bash
# 5分钟标准测试
python3 scripts/run_variant.py moderate --interleaved --benign-duration 300
```

#### 场景3：长时间性能测试
```bash
# 10分钟性能测试
python3 scripts/run_variant.py aggressive --interleaved --benign-duration 600
```

#### 场景4：批量数据集生成
```bash
# 运行所有变体，每个10分钟
python3 scripts/run_all_variants.py --interleaved --benign-duration 600
```

## 监控和调试

### 1. 查看实验状态
```bash
# 查看容器状态
make status

# 查看容器日志
make logs

# 查看特定容器日志
docker logs securitylogs-webapp
docker logs securitylogs-attacker
```

### 2. 验证良性流量
```bash
# 检查良性流量进程
docker exec securitylogs-webapp ps aux | grep -E "(http_traffic|dns_traffic|smtp_traffic)"

# 查看良性流量日志
docker exec securitylogs-webapp tail -f /tmp/benign_traffic.log
```

### 3. 检查网络流量
```bash
# 查看PCAP文件
ls -la data/logs/*/pcap/

# 分析网络流量
tcpdump -r data/logs/*/pcap/*.pcap -c 50
```

## 故障排除

### 1. 常见问题

#### 良性流量启动失败
```bash
# 检查容器状态
docker ps | grep securitylogs-webapp

# 重启容器
make down && make up

# 手动启动良性流量
docker exec securitylogs-webapp bash /opt/scripts/benign_modules/run_benign.sh --help
```

#### 实验中断
```bash
# 清理残留进程
docker exec securitylogs-webapp pkill -f "run_benign.sh"
docker exec securitylogs-webapp pkill -f "http_traffic.sh"

# 重新运行实验
python3 scripts/run_variant.py stealthy --interleaved
```

### 2. 性能优化

#### 减少资源使用
```bash
# 使用较短的持续时间
--benign-duration 60

# 使用简单的协议混合
--benign-mix "HTTP:1.0"
```

#### 增加资源使用
```bash
# 使用较长的持续时间
--benign-duration 1800

# 使用复杂的协议混合
--benign-mix "HTTP:0.4,DNS:0.3,SMTP:0.3"
```

## 最佳实践

### 1. 实验设计
- 根据实验目标选择合适的持续时间
- 根据目标环境配置协议混合比例
- 在长时间实验前进行快速验证

### 2. 数据收集
- 交错模式生成的数据更适合真实环境模拟
- 建议同时收集纯攻击数据和交错数据进行比较
- 记录实验配置参数以便复现

### 3. 性能考虑
- 交错模式会增加系统资源使用
- 长时间实验建议在资源充足的环境中进行
- 监控系统资源使用情况

## 示例工作流

### 完整的安全测试工作流
```bash
# 1. 构建环境
make build

# 2. 启动容器
make up

# 3. 应用网络条件（可选）
make apply-netem

# 4. 运行所有变体（带交错流量）
make run-all-interleaved

# 5. 查看结果
ls -la data/logs/
```

### 快速验证工作流
```bash
# 1. 快速构建
make build

# 2. 快速测试（60秒）
python3 scripts/run_variant.py stealthy --interleaved --benign-duration 60

# 3. 检查结果
ls -la data/logs/lowscan_stealthy/
```

这个集成功能让您的变体实验更加真实和完整，无需手动管理交错流量！ 