# SecurityLogs - 低扫描慢速SQL注入攻击实验平台

## 项目概述

SecurityLogs是一个用于安全实验的容器化平台，专注于"低扫描+慢速SQL注入"攻击场景的数据收集和分析。项目支持多种攻击变体，提供完整的日志收集、ETL处理和自动化实验流程。

## 架构设计

### 1. 容器化隔离

每个攻击变体运行在独立的环境中：
- **Web应用容器** (securitylogs-webapp): NGINX + PHP-FPM
- **攻击者容器** (securitylogs-attacker): 执行SQL注入攻击
- **网络抓包容器** (securitylogs-tcpdump): 捕获网络流量
- **日志聚合容器** (securitylogs-log-aggregator): 收集和转发日志

### 2. 统一日志收集管道

所有日志源都通过统一的Schema进行收集：
- **Web应用日志**: Nginx access/error logs, PHP-FPM logs
- **系统日志**: syslog, auth.log, kernel logs
- **容器日志**: Docker runtime logs
- **攻击日志**: SQL注入攻击结果
- **网络日志**: DNS查询, PCAP文件

### 3. 数据分区与隔离

每个变体的数据存储在独立目录：
```
data/logs/{variant_id}/
├── nginx/
│   ├── access.log
│   └── error.log
├── output/
│   └── container_attack_log.json
├── logs/
│   ├── messages
│   ├── user.log
│   └── syslog
└── pcap/
    └── *.pcap
```

## 支持的攻击变体

| 变体名称 | 变体ID | 描述 | 攻击延迟 |
|---------|--------|------|----------|
| stealthy | lowscan_stealthy | 隐蔽式SQL注入，长延迟 | 5-10秒 |
| moderate | lowscan_moderate | 中等强度SQL注入，中等延迟 | 3-6秒 |
| aggressive | lowscan_aggressive | 激进式SQL注入，短延迟 | 1-3秒 |

## 交错流量功能

SecurityLogs支持交错流量模式，可以在攻击执行期间同时运行良性流量，模拟真实的网络环境。**此功能已默认集成到所有变体实验中**。

### 功能特性

- **默认启用**：所有变体实验自动包含交错流量
- **同时运行**：攻击流量和良性流量同时执行
- **协议混合**：支持HTTP、DNS、SMTP等多种协议
- **可配置比例**：可自定义协议混合比例
- **自动清理**：实验结束后自动停止良性流量
- **网络条件**：自动应用真实网络条件（延迟、丢包、抖动）

### 良性流量配置

#### 协议混合比例
```bash
# 默认配置：HTTP 60%, DNS 30%, SMTP 10%
HTTP:0.6,DNS:0.3,SMTP:0.1

# 自定义配置示例
HTTP:0.8,DNS:0.2                    # 主要HTTP流量
HTTP:0.5,DNS:0.3,SMTP:0.2          # 平衡配置
HTTP:0.7,DNS:0.2,SMTP:0.1          # 高HTTP比例
```

#### 持续时间配置
```bash
# 默认：300秒（5分钟）
--benign-duration 300

# 自定义示例
--benign-duration 60    # 1分钟（快速测试）
--benign-duration 600   # 10分钟（长时间实验）
--benign-duration 1800  # 30分钟（扩展实验）
```

### 使用场景

1. **真实环境模拟**：模拟生产环境中的正常流量
2. **检测系统测试**：测试安全检测系统在混合流量中的表现
3. **数据质量提升**：生成更真实的训练数据集
4. **性能基准测试**：评估系统在高负载下的性能

## 统一Schema定义

所有日志都映射到以下统一Schema：

| 字段名 | 类型 | 说明 |
|--------|------|------|
| timestamp | string | ISO8601 UTC时间 |
| variant_id | string | 攻击变体标识 |
| host | string | 主机名或容器ID |
| source_type | string | 日志源类型 (web, system, container, network) |
| event_type | string | 事件类型 (HTTP_REQUEST, SQL_QUERY, LOGIN_ATTEMPT等) |
| severity | string | 严重程度 (INFO, WARN, ERROR, ALERT) |
| process | string | 进程名+PID |
| user | string | 发起事件的用户名 |
| details | object | 原始日志解析出的JSON KV |
| is_attack | boolean | 是否为攻击事件 |
| attack_stage | string | 攻击阶段 (reconnaissance, exploit, exfiltration) |

### 示例日志记录

```json
{
  "timestamp": "2025-07-14T02:05:23Z",
  "variant_id": "lowscan_stealthy",
  "host": "webapp-1",
  "source_type": "web",
  "event_type": "HTTP_REQUEST",
  "severity": "INFO",
  "process": "nginx[1234]",
  "user": "-",
  "details": {
    "method": "GET",
    "url": "/login",
    "status": 200
  },
  "is_attack": false
}
```

## 快速开始

### 1. 环境准备

```bash
# 克隆项目
git clone <repository-url>
cd SecurityLogs

# 构建Docker镜像（已配置host网络解决网络问题）
make build

# 启动基础环境
make up
```

### 网络问题解决方案

如果在构建过程中遇到网络超时问题，项目已配置以下解决方案：

#### 方案1: 使用Host网络构建（默认配置）
```bash
# 项目已配置host网络构建，直接使用即可
make build
```

#### 方案2: 清理缓存后重试
```bash
# 清理Docker缓存
docker system prune -a -f
docker builder prune -a -f

# 重新构建
make build
```

#### 方案3: 使用国内镜像源（备选）
如果host网络方案不可用，可以临时启用国内镜像源：
```bash
# 修改Dockerfile中的注释行，启用国内镜像源
# 然后重新构建
make build
```

详细解决方案请参考：[网络问题解决方案](docs/troubleshooting/network_issues.md)

### 2. 运行单个变体

```bash
# 使用Python脚本（手动控制）
python3 scripts/run_variant.py stealthy --interleaved --benign-duration 300
python3 scripts/run_variant.py moderate --interleaved --benign-mix "HTTP:0.7,DNS:0.2,SMTP:0.1"
python3 scripts/run_variant.py aggressive --interleaved --benign-duration 600

# 使用Makefile（推荐 - 自动包含交错流量和网络条件）
make run-variant VARIANT=stealthy
make run-variant VARIANT=moderate
make run-variant VARIANT=aggressive

# 自定义参数
make run-variant VARIANT=stealthy BENIGN_DURATION=300
make run-variant VARIANT=moderate BENIGN_MIX="HTTP:0.8,DNS:0.2"
```



### 5. Makefile完整命令参考

```bash
# 查看所有可用命令
make help

# 构建相关
make build              # 构建所有镜像（使用host网络）
make build-clean        # 清理缓存并重新构建（解决网络问题）
make clean              # 清理容器和镜像

# 核心运行命令（自动包含交错流量和网络条件）
make up                 # 启动容器
make down               # 停止容器
make run-variant VARIANT=stealthy    # 运行单个变体（自动包含交错流量和网络条件）
make run-all-variants               # 运行所有变体（自动包含交错流量和网络条件）
make run-variants VARIANTS='stealthy moderate'  # 运行指定变体（自动包含交错流量和网络条件）

# 自定义参数
make run-variant VARIANT=stealthy BENIGN_DURATION=300
make run-all-variants BENIGN_MIX="HTTP:0.7,DNS:0.2,SMTP:0.1"

# 监控
make logs               # 查看容器日志
make status             # 查看容器状态

# 完整工作流
make all                # 完整攻击工作流（构建+运行+分析）
```

### 6. 生成真实数据集的运行选项

#### 一键生成（推荐）
```bash
# 最简单的方式 - 自动包含交错流量和网络条件
make build
make run-all-variants
```

#### 完整工作流
```bash
# 方式1：一键完成（推荐）
make all

# 方式2：分步执行（更灵活）
make build              # 构建镜像
make up                 # 启动容器
make run-all-variants   # 运行所有变体（自动包含交错流量和网络条件）
```

#### 高级真实环境配置
```bash
# 自定义网络条件
sudo make apply-netem DELAY=200 LOSS=2 JITTER=50 BANDWIDTH=5

# 运行特定变体组合
make run-variants VARIANTS='stealthy aggressive'

# 查看实时状态
make status
make logs
```

#### 网络条件说明
- **`apply-netem`**: 为容器网络添加真实网络条件
  - 延迟：模拟网络延迟（默认100ms）
  - 丢包：模拟网络丢包（默认1%）
  - 抖动：模拟网络抖动（默认20ms）
  - 带宽：限制网络带宽（默认10Mbps）

#### 数据真实性对比

| 运行方式 | 攻击数据 | 正常流量 | 网络条件 | 数据真实性 |
|---------|---------|---------|---------|-----------|
| `make run-all-variants` | ✅ | ❌ | ❌ | 基础 |
| `make all` | ✅ | ✅ | ✅ | **高** |
| 自定义配置 | ✅ | ✅ | ✅ | **最高** |

#### 推荐的数据集生成流程

```bash
# 1. 清理环境（如果需要）
make clean

# 2. 构建镜像
make build

# 3. 生成真实数据集（推荐）
make all

# 4. 验证结果
ls -la data/datasets/
ls -la data/logs/
```

#### 最佳实践建议

**对于研究用途**：
```bash
# 生成高质量研究数据集
make build
sudo make apply-netem DELAY=100 LOSS=1 JITTER=20 BANDWIDTH=10
make run-all-variants
```

**对于生产环境模拟**：
```bash
# 模拟生产网络环境
make build
sudo make apply-netem DELAY=50 LOSS=0.5 JITTER=10 BANDWIDTH=50
make run-all-variants
```

**对于性能测试**：
```bash
# 生成性能测试数据集
make build
sudo make apply-netem DELAY=10 LOSS=0.1 JITTER=5 BANDWIDTH=100
make run-all-variants
```

**对于机器学习训练**：
```bash
# 生成ML训练数据集（包含多种网络条件）
for delay in 50 100 200; do
    for loss in 0.1 0.5 1.0; do
        sudo make apply-netem DELAY=$delay LOSS=$loss
        make run-all-variants
        sleep 60
    done
done
```

#### 数据集质量检查
```bash
# 检查生成的数据集
ls -la data/datasets/*_dataset.jsonl

# 查看数据集统计
ls -la data/datasets/*_stats.json

# 检查日志完整性
ls -la data/logs/*/

# 验证网络抓包文件
ls -la data/pcap/*.pcap
```

### 3. 批量运行所有变体

```bash
# 使用Python脚本（手动控制）
python3 scripts/run_all_variants.py --interleaved
python3 scripts/run_all_variants.py --variants stealthy moderate --interleaved

# 使用Makefile（推荐 - 自动包含交错流量和网络条件）
make run-all-variants
make run-variants VARIANTS='stealthy moderate'

# 自定义参数
make run-all-variants BENIGN_DURATION=600
make run-variants VARIANTS='stealthy moderate' BENIGN_MIX="HTTP:0.7,DNS:0.2,SMTP:0.1"
```

### 4. 高级选项

#### Python脚本高级选项
```bash
# 跳过ETL处理
python3 scripts/run_variant.py stealthy --skip-etl

# 设置重试次数
python3 scripts/run_all_variants.py --max-retries 3

# 指定场景目录
python3 scripts/run_variant.py stealthy --scenario-dir scenarios/low-and-slow-sqli
```

#### 网络条件高级配置
```bash
# 自定义网络延迟和丢包
sudo make apply-netem DELAY=150 LOSS=0.5 JITTER=30 BANDWIDTH=20

# 模拟恶劣网络环境
sudo make apply-netem DELAY=500 LOSS=5 JITTER=100 BANDWIDTH=2

# 模拟良好网络环境
sudo make apply-netem DELAY=10 LOSS=0.1 JITTER=5 BANDWIDTH=100

# 重置网络条件
sudo make reset-netem
```

#### 变体组合运行
```bash
# 运行特定变体组合
make run-variants VARIANTS='stealthy moderate'

# 只运行激进变体
make run-variant VARIANT=aggressive

# 运行所有变体但跳过ETL
python3 scripts/run_all_variants.py --skip-etl
```

## 数据收集流程

### 1. 实验执行
1. 自动生成变体配置
2. 创建独立目录结构
3. 启动容器环境
4. 执行攻击脚本
5. 收集各类日志

### 2. ETL处理
1. **主机日志ETL**: 处理syslog, auth.log, kernel logs
2. **容器日志ETL**: 处理Docker runtime logs
3. **应用日志ETL**: 处理Nginx, PHP-FPM logs
4. **攻击日志ETL**: 处理SQL注入攻击结果
5. **DNS日志ETL**: 处理DNS查询日志

### 3. 数据输出
处理后的数据存储在 `data/raw/` 目录：
```
data/raw/
├── attack_logs/
│   └── attack_results.jsonl
├── application_logs/
│   ├── nginx_access.jsonl
│   ├── nginx_error.jsonl
│   ├── php_fpm.jsonl
│   └── syslog.jsonl
├── container_logs/
│   ├── securitylogs-webapp.jsonl
│   ├── securitylogs-attacker.jsonl
│   └── securitylogs-log-aggregator.jsonl
├── host_logs/
│   ├── auth.jsonl
│   └── syslog.jsonl
└── dns_logs/
    └── dnsmasq_*.jsonl
```

## 攻击标注机制

### 1. 时间窗口标注
- 攻击脚本明确标记攻击开始/结束时间
- ETL处理时根据时间窗口自动标注 `is_attack` 字段

### 2. 关键词标注
- 基于日志内容关键词自动识别攻击事件
- SQL注入相关关键词: `union`, `select`, `or 1=1`, `admin'` 等

### 3. 攻击阶段标注
- `reconnaissance`: 侦察阶段
- `exploit`: 攻击利用阶段
- `exfiltration`: 数据窃取阶段

## 数据质量保证

### 1. 真实环境模拟
- **网络条件模拟**: 通过 `apply-netem` 添加真实网络延迟、丢包、抖动
- **混合流量**: 攻击流量与正常流量混合，更接近真实环境
- **时间同步**: 所有日志使用统一的时间戳格式

### 2. 数据完整性
- **多源日志收集**: Web应用、系统、容器、网络等多维度日志
- **PCAP抓包**: 完整的网络流量捕获
- **统一Schema**: 所有数据转换为标准JSON Lines格式

### 3. 数据标注质量
- **自动标注**: 基于时间窗口和关键词的自动攻击标注
- **MITRE映射**: 自动映射到MITRE ATT&CK框架
- **网络五元组**: 完整的网络连接信息提取

### 4. 数据验证
```bash
# 验证数据集完整性
python3 scripts/validate_dataset.py data/datasets/*_dataset.jsonl

# 检查数据质量指标
python3 scripts/data_quality_check.py

# 生成数据质量报告
python3 scripts/generate_quality_report.py
```

## 目录结构

```
SecurityLogs/
├── scenarios/
│   └── low-and-slow-sqli/
│       ├── docker-compose.yml
│       └── docker-compose.override.yml
├── scripts/
│   ├── attack/
│   │   └── container_attack.py
│   ├── data_processing/
│   │   ├── run_all_etl.py
│   │   ├── etl_attack_logs.py
│   │   ├── etl_application_logs.py
│   │   ├── etl_container_logs.py
│   │   ├── etl_host_logs.py
│   │   └── parse_dns_logs.py
│   ├── run_variant.py
│   └── run_all_variants.py
├── containers/
│   ├── webapp/
│   ├── attacker/
│   └── tcpdump/
├── data/
│   ├── logs/
│   ├── raw/
│   ├── datasets/
│   └── output/
├── Makefile
└── README.md
```

## 故障排除

### 常见问题

1. **容器启动失败**
   ```bash
   # 检查容器状态
   docker ps -a
   
   # 查看容器日志
   docker logs securitylogs-webapp
   ```

2. **权限问题**
   ```bash
   # 修复目录权限
   sudo chown -R 1000:1000 data/logs/
   sudo chmod -R 777 data/logs/
   ```

3. **ETL处理失败**
   ```bash
   # 单独运行ETL脚本
   python3 scripts/data_processing/etl_attack_logs.py --variant-id lowscan_stealthy
   ```

### 日志位置

- **容器日志**: `docker logs <container-name>`
- **应用日志**: `data/logs/{variant_id}/nginx/`
- **系统日志**: `data/logs/{variant_id}/messages`
- **攻击日志**: `data/logs/{variant_id}/output/container_attack_log.json`
- **网络日志**: `data/logs/{variant_id}/pcap/`

## 扩展开发

### 添加新变体

1. 在 `scripts/run_variant.py` 的 `VARIANT_CONFIGS` 中添加新变体
2. 修改攻击脚本以支持新的攻击参数
3. 更新文档和Makefile

### 添加新日志源

1. 创建新的ETL脚本
2. 在 `scripts/data_processing/run_all_etl.py` 中注册
3. 确保输出符合统一Schema

### 自定义攻击脚本

1. 修改 `scripts/attack/container_attack.py`
2. 添加新的攻击载荷或技术
3. 确保输出包含攻击时间标记

## 贡献指南

1. Fork项目
2. 创建功能分支
3. 提交更改
4. 创建Pull Request

## 许可证

[许可证信息]

## 联系方式

[联系信息]
