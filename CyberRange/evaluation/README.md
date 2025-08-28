# CyberRange Dataset Quality Evaluation Module

## 概述

evaluation模块用于评估CyberRange生成的网络安全数据集的质量。通过与开源工具Fiberfox生成的基准数据集进行对比，并使用多种IDS工具进行检测验证，全面评估数据集的质量。

## 主要功能

### 1. 数据集质量评估
- **PCAP文件分析**：提取流量特征、协议分布、时间模式等
- **Ground Truth验证**：从nginx detailed.log提取GT标签并验证准确性
- **多维度质量指标**：包括检测准确性、标签质量、数据多样性、时间质量、攻击真实性

### 2. 基准数据集对比
- **Fiberfox集成**：自动生成或加载Fiberfox基准PCAP文件
- **特征对比**：比较CyberRange与Fiberfox数据集的流量特征
- **相似度分析**：计算数据集之间的相似度分数

### 3. IDS检测评估
- **多IDS支持**：目前支持Suricata，未来可扩展Snort、Zeek等
- **检测性能评估**：计算精确率、召回率、F1分数等指标
- **GT验证**：将IDS检测结果与Ground Truth标签对比验证

### 4. 综合报告生成
- **多格式输出**：JSON、HTML、Markdown格式报告
- **可视化展示**：图表展示质量指标和检测结果
- **改进建议**：基于评估结果提供优化建议

## 安装

### 1. 安装依赖

```bash
cd /home/jiayi/SecurityLogs/CyberRange/evaluation
pip install -r requirements.txt
```

### 2. 安装IDS工具（可选）

安装Suricata：
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install suricata

# 或从源码安装最新版本
# 参考：https://suricata.io/download/
```

### 3. 配置Fiberfox（如需生成基准数据）

确保Fiberfox工具已正确安装在analysis目录下。

## 使用方法

### 快速开始

#### 1. 创建配置文件

```bash
# 复制示例配置
cp evaluation_config_example.yaml evaluation_config.yaml

# 编辑配置文件，设置正确的路径
vim evaluation_config.yaml
```

#### 2. 运行评估

```bash
# 使用配置文件运行完整评估
python evaluate.py --config evaluation_config.yaml

# 或直接指定文件路径
python evaluate.py \
    --cyberrange-pcap /path/to/your/pcap \
    --cyberrange-gt /path/to/nginx_detailed.csv
```

### 生成基准数据集

如果需要生成新的Fiberfox基准数据：

```bash
# 生成所有攻击策略的PCAP
python generate_baseline.py http://your-target:port

# 生成特定策略
python generate_baseline.py http://your-target:port --strategy SLOW --duration 120

# 验证Fiberfox安装
python generate_baseline.py http://localhost --verify-only
```

### 命令行选项

#### evaluate.py
- `--config`: 配置文件路径（默认：evaluation_config.yaml）
- `--cyberrange-pcap`: 覆盖配置中的CyberRange PCAP路径
- `--cyberrange-gt`: 覆盖配置中的GT日志路径
- `--skip-baseline`: 跳过基准数据集评估
- `--skip-ids`: 跳过IDS检测

#### generate_baseline.py
- `target`: 目标URL（必需）
- `--strategy`: 特定攻击策略（SLOW/GET/BYPASS/AVB）
- `--duration`: 持续时间（秒）
- `--output`: 输出目录
- `--max-size`: 最大文件大小（MB）
- `--verify-only`: 仅验证Fiberfox安装

## 配置说明

### 主要配置项

```yaml
datasets:
  cyberrange:
    pcap_path: "PCAP文件路径"
    gt_log_path: "Ground Truth CSV文件路径"

baseline:
  generate_fiberfox: false  # 是否生成新的基准数据
  existing_pcaps:          # 已有的基准PCAP路径
    SLOW: "/path/to/slow.pcap"
    GET: "/path/to/get.pcap"

detection:
  enabled: true            # 启用IDS检测
  detectors:
    suricata: true        # 使用Suricata
  time_tolerance: 5.0      # 时间匹配容差

output:
  directory: "./results"   # 输出目录
  formats: [json, html, markdown]  # 报告格式
```

## 输出说明

### 目录结构

```
evaluation_results/
├── evaluation/                    # 核心评估结果
│   ├── cyberrange_gt.csv        # 导出的GT数据
│   └── evaluation_results_*.json # 主评估结果
├── ids_results/                  # IDS检测结果
│   └── suricata/                # Suricata检测输出
├── baseline_pcaps/               # 基准PCAP文件（如果生成）
├── evaluation_report.html        # HTML报告
├── EVALUATION_SUMMARY.md         # Markdown摘要
└── evaluation.log               # 运行日志
```

### 质量评分说明

- **A+ (95-100%)**: 卓越质量，适合研究和生产使用
- **A (90-94%)**: 优秀质量，仅需少量改进
- **B (75-89%)**: 良好质量，某些方面需要改进
- **C (60-74%)**: 可接受质量，需要较多改进
- **D (50-59%)**: 质量较差，需要大幅改进
- **F (<50%)**: 质量不合格，需要重新生成

## 扩展开发

### 添加新的IDS工具

1. 在`detection/`目录创建新的检测器类
2. 继承基类并实现`detect()`方法
3. 在`ids_manager.py`中注册新检测器

### 添加新的质量指标

1. 在`metrics_calculator.py`中添加新的计算方法
2. 更新权重配置
3. 在报告生成中包含新指标

## 故障排除

### 常见问题

1. **Suricata未找到**
   - 确保Suricata已安装并在PATH中
   - 或在代码中指定完整路径

2. **PCAP文件过大**
   - 调整`advanced.max_pcap_size`配置
   - 启用`memory_optimization`选项

3. **Fiberfox生成失败**
   - 检查目标URL是否可访问
   - 验证Fiberfox依赖是否完整

## 许可证

本项目遵循与CyberRange主项目相同的许可证。
