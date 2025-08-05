# CyberRange 自动化脚本

## 快速使用

### 1. 一键清理
```bash
./scripts/clean.sh
```
清除所有日志、数据和容器

### 2. 一键运行完整实验
```bash
./scripts/run_experiment.sh scenarios/modular_demo_detailed.yaml
```
自动执行：清理 → 运行实验 → 解析转换

### 3. 一键解析数据
```bash
./scripts/parse_data.sh
```
将最新实验数据转换为CSV格式

### 4. 检查系统状态
```bash
./scripts/status.sh
```
查看容器、日志和数据状态

## 脚本说明

- `clean.sh` - 清理环境
- `run_experiment.sh` - 完整实验流程
- `parse_data.sh` - 数据解析转换
- `status.sh` - 系统状态检查 