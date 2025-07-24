# SecurityLogs Multi-Variant Dataset

## Dataset Overview

This dataset contains multiple variant experiments of "low-and-slow SQL injection" attack scenarios, with each variant running in isolated container environments to ensure data independence and reproducibility.

## 实验设计

### Attack Variants

1. **lowscan_stealthy** - Stealthy Attack
   - Nmap扫描速率: 0.008 packets/sec
   - SQL注入延迟: 300秒
   - SQLMap参数: RISK=1, LEVEL=1
   - 网络延迟: 5ms

2. **lowscan_moderate** - Moderate Intensity Attack
   - Nmap扫描速率: 0.016 packets/sec
   - SQL注入延迟: 120秒
   - SQLMap参数: RISK=1, LEVEL=2
   - 网络延迟: 50ms

3. **lowscan_aggressive** - Aggressive Attack
   - Nmap扫描速率: 0.032 packets/sec
   - SQL注入延迟: 60秒
   - SQLMap参数: RISK=2, LEVEL=3
   - 网络延迟: 200ms

### Data Sources

Each variant contains the following data sources:
- **Host Logs**: syslog, auth.log, kern.log
- **Container Logs**: webapp, attacker, tcpdump, log-aggregator
- **Application Logs**: nginx access/error, php-fpm
- **Attack Logs**: SQLMap, Nmap, custom attack scripts
- **网络流量**: PCAP文件

## Data Format

### 统一Schema

All logs are converted to unified JSON Lines format with the following fields:

| Field Name | Type | Description | Example |
|--------|------|-------------|---------|
| timestamp | string | ISO8601 UTC时间 | "2025-07-14T09:10:00Z" |
| variant_id | string | Variant identifier | "lowscan_stealthy" |
| host | string | 主机名 | "linux1" |
| source_type | string | Log source type | "webapp", "attacker", "network" |
| event_type | string | 事件类型 | "sql_injection", "network_scan" |
| severity | string | Log level | "info", "warn", "error" |
| process | string | 进程名 | "nginx", "sqlmap" |
| user | string | 用户名 | "attacker", "www-data" |
| is_attack | string | Attack indicator | "Exploit", "Recon", null |
| attack_stage | string | Attack stage | "reconnaissance", "exploit", "exfiltration" |
| details | object | Additional details | Original logs or structured data |

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
├── logs/                    # Raw log files
│   ├── lowscan_stealthy/   # Stealthy variant logs
│   ├── lowscan_moderate/   # Moderate intensity variant logs
│   └── lowscan_aggressive/ # Aggressive variant logs
├── datasets/               # Unified format datasets
│   ├── lowscan_stealthy_dataset.jsonl
│   ├── lowscan_moderate_dataset.jsonl
│   ├── lowscan_aggressive_dataset.jsonl
│   └── *_stats.json       # 统计信息
└── host_logs/             # Host system logs
    ├── syslog.jsonl
    ├── auth.log.jsonl
    └── kern.log.jsonl
```

## 使用方法

### 运行实验

```bash
# Run single variant
./experiments/run_variant.sh lowscan_stealthy

# Run all variants
./experiments/run_all_variants.sh
```

### Data Analysis

```bash
# View dataset statistics
python3 data/merge_variant_logs.py --variant-id lowscan_stealthy \
  --input-dir data/logs/lowscan_stealthy \
  --output-file data/datasets/lowscan_stealthy_dataset.jsonl

# Analyze attack events
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

# Load dataset
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
    
    # Attack features
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

### Data Integrity Check

- Each variant contains complete attack chain logs
- 时间戳统一为UTC格式
- Attack events are automatically labeled
- Container isolation ensures data independence

### 可重现性

- 所有实验参数版本化
- 容器镜像固定版本
- 网络条件可配置
- 随机种子固定

## 扩展指南

### Adding New Variants

1. Add new variant configuration in `experiments/variants.yml`
2. Run `./experiments/run_all_variants.sh` to automatically include new variants

### Adding New Data Sources

1. 修改 `data/merge_variant_logs.py` 添加新的解析逻辑
2. 更新统一Schema文档
3. 重新运行ETL流程

### 自定义分析

1. 基于统一Schema开发分析脚本
2. Use `variant_id` field for variant comparison
3. Use `is_attack` and `attack_stage` for attack analysis

## 注意事项

- 实验环境仅用于研究和教育目的
- Do not run attack scripts in production environments
- The dataset contains sensitive information, please handle with care
- 建议在隔离的测试环境中使用

## 联系信息

如有问题或建议，请通过项目Issues联系。 