# SecurityLogs 简化使用指南

## 概述

SecurityLogs已经简化了使用流程，将交错流量和网络条件功能默认集成到所有变体实验中，无需手动选择。

## 快速开始

### 1. 构建环境
```bash
# 构建所有Docker镜像
make build
```

### 2. 运行实验

#### 运行单个变体
```bash
# 运行stealthy变体（自动包含交错流量和网络条件）
make run-variant VARIANT=stealthy

# 运行moderate变体
make run-variant VARIANT=moderate

# 运行aggressive变体
make run-variant VARIANT=aggressive
```

#### 运行所有变体
```bash
# 运行所有变体（自动包含交错流量和网络条件）
make run-all-variants
```

#### 运行指定变体组合
```bash
# 运行stealthy和moderate变体
make run-variants VARIANTS='stealthy moderate'

# 运行moderate和aggressive变体
make run-variants VARIANTS='moderate aggressive'
```

### 3. 自定义参数

#### 自定义良性流量持续时间
```bash
# 60秒（快速测试）
make run-variant VARIANT=stealthy BENIGN_DURATION=60

# 10分钟（长时间实验）
make run-variant VARIANT=stealthy BENIGN_DURATION=600
```

#### 自定义协议混合比例
```bash
# 主要HTTP流量
make run-variant VARIANT=stealthy BENIGN_MIX="HTTP:0.8,DNS:0.2"

# 平衡配置
make run-variant VARIANT=stealthy BENIGN_MIX="HTTP:0.5,DNS:0.3,SMTP:0.2"
```

#### 批量自定义
```bash
# 所有变体使用自定义配置
make run-all-variants BENIGN_DURATION=600 BENIGN_MIX="HTTP:0.7,DNS:0.2,SMTP:0.1"

# 指定变体使用自定义配置
make run-variants VARIANTS='stealthy moderate' BENIGN_DURATION=300
```

## 完整工作流

### 一键完成
```bash
# 构建 + 运行所有变体 + 数据分析
make all
```

### 分步执行
```bash
# 1. 构建环境
make build

# 2. 启动容器
make up

# 3. 运行所有变体
make run-all-variants

# 4. 查看结果
ls -la data/logs/
```

## 监控和调试

### 查看状态
```bash
# 查看容器状态
make status

# 查看容器日志
make logs
```

### 清理环境
```bash
# 停止容器
make down

# 清理所有容器和镜像
make clean
```

## 使用场景

### 快速测试
```bash
# 60秒快速测试
make run-variant VARIANT=stealthy BENIGN_DURATION=60
```

### 标准实验
```bash
# 5分钟标准实验
make run-variant VARIANT=moderate
```

### 批量数据集生成
```bash
# 运行所有变体，生成完整数据集
make run-all-variants
```

### 研究实验
```bash
# 自定义配置的研究实验
make run-variants VARIANTS='stealthy aggressive' BENIGN_DURATION=900 BENIGN_MIX="HTTP:0.6,DNS:0.3,SMTP:0.1"
```

## 自动化特性

### 默认包含的功能
- ✅ **交错流量**：自动运行良性流量（HTTP、DNS、SMTP）
- ✅ **网络条件**：自动应用真实网络条件（延迟、丢包、抖动）
- ✅ **数据收集**：自动收集所有日志和PCAP文件
- ✅ **清理机制**：实验结束后自动清理资源

### 无需手动操作
- ❌ 不需要手动启动良性流量
- ❌ 不需要手动应用网络条件
- ❌ 不需要手动管理进程
- ❌ 不需要手动清理资源

## 故障排除

### 常见问题

#### 构建失败
```bash
# 清理缓存后重新构建
make build-clean
```

#### 容器启动失败
```bash
# 检查容器状态
make status

# 重启容器
make down && make up
```

#### 权限问题
```bash
# 修复目录权限
sudo chown -R 1000:1000 data/logs/
sudo chmod -R 777 data/logs/
```

## 最佳实践

### 1. 实验设计
- 使用 `make run-variant` 进行单个变体测试
- 使用 `make run-all-variants` 进行完整数据集生成
- 使用 `make all` 进行完整工作流

### 2. 参数配置
- 快速测试：`BENIGN_DURATION=60`
- 标准实验：使用默认参数
- 长时间实验：`BENIGN_DURATION=600` 或更高

### 3. 资源管理
- 实验完成后使用 `make down` 停止容器
- 定期使用 `make clean` 清理环境
- 监控系统资源使用情况

## 示例工作流

### 完整的安全测试
```bash
# 1. 构建环境
make build

# 2. 运行所有变体
make run-all-variants

# 3. 查看结果
ls -la data/logs/
make status
```

### 快速功能验证
```bash
# 1. 快速构建
make build

# 2. 快速测试
make run-variant VARIANT=stealthy BENIGN_DURATION=60

# 3. 检查结果
ls -la data/logs/lowscan_stealthy/
```

### 自定义研究实验
```bash
# 1. 构建环境
make build

# 2. 自定义实验
make run-variants VARIANTS='stealthy aggressive' BENIGN_DURATION=900 BENIGN_MIX="HTTP:0.7,DNS:0.2,SMTP:0.1"

# 3. 分析结果
ls -la data/logs/
```

现在使用SecurityLogs变得非常简单！只需要几个命令就能完成复杂的网络安全实验。 