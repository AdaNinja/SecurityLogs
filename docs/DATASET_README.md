# SecurityLogs Multi-Variant Dataset

## 概述

本数据集包含"低扫描+慢速SQL注入"攻击场景的多个变体实验，每个变体都在隔离的容器环境中运行，确保数据独立性和可重现性。

## 实验设计

### 攻击变体

1. **lowscan_stealthy** - 隐秘型攻击
   - Nmap扫描速率: 0.008 packets/sec
   - SQL注入延迟: 300秒
   - SQLMap参数: RISK=1, LEVEL=1
   - 网络延迟: 5ms

2. **lowscan_moderate** - 中等强度攻击
   - Nmap扫描速率: 0.016 packets/sec
   - SQL注入延迟: 120秒
   - SQLMap参数: RISK=1, LEVEL=2
   - 网络延迟: 50ms

3. **lowscan_aggressive** - 激进型攻击
   - Nmap扫描速率: 0.032 packets/sec
   - SQL注入延迟: 60秒
   - SQLMap参数: RISK=2, LEVEL=3
   - 网络延迟: 200ms

### 数据源

每个变体包含以下数据源：
- **主机日志**: syslog, auth.log, kern.log
- **容器日志**: webapp, attacker, tcpdump, log-aggregator
- **应用日志**: nginx access/error, php-fpm
- **攻击日志**: SQLMap, Nmap, 自定义攻击脚本
- **网络流量**: PCAP文件

## 数据格式

### 统一Schema

所有日志都转换为统一的JSON Lines格式，字段如下：

| 字段名 | 类型 | 说明 | 示例 |
|--------|------|------|------|
| timestamp | string | ISO8601 UTC时间 | "2025-07-14T09:10:00Z" |
| variant_id | string | 变体标识 | "lowscan_stealthy" |
| host | string | 主机名 | "linux1" |
| source_type | string | 日志来源类型 | "webapp", "attacker", "network" |
| event_type | string | 事件类型 | "sql_injection", "network_scan" |
| severity | string | 日志级别 | "info", "warn", "error" |
| process | string | 进程名 | "nginx", "sqlmap" |
| user | string | 用户名 | "attacker", "www-data" |
| is_attack | string | 攻击标识 | "Exploit", "Recon", null |
| attack_stage | string | 攻击阶段 | "reconnaissance", "exploit", "exfiltration" |
| details | object | 详细信息 | 原始日志或结构化数据 |

### 示例记录

```json
{
  "timestamp": "2025-07-14T09:10:00Z",
  "variant_id": "lowscan_stealthy",
  "host": "linux1",
  "source_type": "attacker",
  "event_type": "sql_injection",
  "severity": "error",
  "process": "sqlmap",
  "user": "attacker",
  "is_attack": "Exploit",
  "attack_stage": "exploit",
  "details": {
    "raw": "SQL injection attempt: admin' OR '1'='1",
    "payload": "admin' OR '1'='1",
    "success": true
  }
}
```

## 文件结构

```
data/
├── logs/                    # 原始日志文件
│   ├── lowscan_stealthy/   # 隐秘型变体日志
│   ├── lowscan_moderate/   # 中等强度变体日志
│   └── lowscan_aggressive/ # 激进型变体日志
├── datasets/               # 统一格式数据集
│   ├── lowscan_stealthy_dataset.jsonl
│   ├── lowscan_moderate_dataset.jsonl
│   ├── lowscan_aggressive_dataset.jsonl
│   └── *_stats.json       # 统计信息
└── host_logs/             # 主机系统日志
    ├── syslog.jsonl
    ├── auth.log.jsonl
    └── kern.log.jsonl
```

## 使用方法

### 运行实验

```bash
# 运行单个变体
./experiments/run_variant.sh lowscan_stealthy

# 运行所有变体
./experiments/run_all_variants.sh
```

### 数据分析

```bash
# 查看数据集统计
python3 data/merge_variant_logs.py --variant-id lowscan_stealthy \
  --input-dir data/logs/lowscan_stealthy \
  --output-file data/datasets/lowscan_stealthy_dataset.jsonl

# 分析攻击事件
python3 -c "
import json
with open('data/datasets/lowscan_stealthy_dataset.jsonl') as f:
    attacks = [json.loads(line) for line in f if json.loads(line).get('is_attack')]
print(f'Found {len(attacks)} attack events')
"
```

### 机器学习应用

```python
import json
import pandas as pd

# 加载数据集
def load_variant_dataset(variant_id):
    records = []
    with open(f'data/datasets/{variant_id}_dataset.jsonl') as f:
        for line in f:
            records.append(json.loads(line))
    return pd.DataFrame(records)

# 特征工程
def extract_features(df):
    # 时间特征
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    
    # 攻击特征
    df['is_attack_bool'] = df['is_attack'].notna()
    df['attack_stage_encoded'] = df['attack_stage'].astype('category').cat.codes
    
    return df

# 使用示例
df = load_variant_dataset('lowscan_stealthy')
df = extract_features(df)
print(f"Dataset shape: {df.shape}")
print(f"Attack events: {df['is_attack_bool'].sum()}")
```

## 质量控制

### 数据完整性检查

- 每个变体包含完整的攻击链日志
- 时间戳统一为UTC格式
- 攻击事件自动标注
- 容器隔离确保数据独立性

### 可重现性

- 所有实验参数版本化
- 容器镜像固定版本
- 网络条件可配置
- 随机种子固定

## 扩展指南

### 添加新变体

1. 在 `experiments/variants.yml` 中添加新变体配置
2. 运行 `./experiments/run_all_variants.sh` 自动包含新变体

### 添加新数据源

1. 修改 `data/merge_variant_logs.py` 添加新的解析逻辑
2. 更新统一Schema文档
3. 重新运行ETL流程

### 自定义分析

1. 基于统一Schema开发分析脚本
2. 利用 `variant_id` 字段进行变体比较
3. 使用 `is_attack` 和 `attack_stage` 进行攻击分析

## 注意事项

- 实验环境仅用于研究和教育目的
- 请勿在生产环境中运行攻击脚本
- 数据集包含敏感信息，请妥善保管
- 建议在隔离的测试环境中使用

## 联系信息

如有问题或建议，请通过项目Issues联系。 