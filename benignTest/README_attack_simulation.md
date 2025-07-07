# 攻击场景模拟使用指南

## 📋 概述

本指南介绍如何使用攻击模拟脚本来生成与学姐提供的FiberFox工具相似的攻击数据，用于与良性活动数据进行对比分析。

## 🎯 目标

1. **模拟真实攻击模式**：模仿FiberFox的SLOW、GET、BYPASS策略
2. **生成对比数据**：为安全日志分析提供恶意流量基准
3. **验证检测能力**：测试分析工具是否能区分正常和异常流量

## 🛠️ 脚本说明

### 1. `attack_simulation.py` - 攻击模拟器

**功能**：
- 模拟三种攻击类型：慢速HTTP、GET洪水、绕过攻击
- 自动捕获网络流量（PCAP格式）
- 生成详细的攻击日志

**攻击类型**：

#### 🐌 SLOW HTTP Attack
- **特点**：模拟慢速HTTP攻击，类似FiberFox的SLOW策略
- **行为**：发送缓慢的HTTP请求，占用服务器连接
- **参数**：5个并发连接，2-4秒间隔

#### 🌊 GET Flood Attack  
- **特点**：模拟GET洪水攻击，类似FiberFox的GET策略
- **行为**：快速发送大量GET请求
- **参数**：10个并发连接，0.1秒间隔

#### 🚪 BYPASS Attack
- **特点**：模拟绕过攻击，类似FiberFox的BYPASS策略
- **行为**：尝试各种绕过技术（IP伪造、User-Agent伪装等）
- **参数**：3个并发连接，多种绕过技术轮换

### 2. `compare_benign_vs_attack.py` - 对比分析器

**功能**：
- 分析良性活动和攻击活动的特征差异
- 生成详细的对比报告
- 提供检测建议和洞察

## 🚀 使用步骤

### 步骤1：运行攻击模拟

```bash
# 确保在benignTest目录下
cd /home/jiayi/SecurityLogs/benignTest

# 运行攻击模拟（需要sudo权限用于tcpdump）
sudo python3 attack_simulation.py
```

**预期输出**：
```
🎯 Starting comprehensive attack simulation...
🚀 Starting SLOW HTTP attack simulation for 300s...
📡 Started traffic capture: attack_test/slow_http/attack_traffic.pcap
✅ SLOW HTTP attack simulation completed
🚀 Starting GET flood attack simulation for 300s...
📡 Started traffic capture: attack_test/get_flood/attack_traffic.pcap
✅ GET flood attack simulation completed
🚀 Starting BYPASS attack simulation for 300s...
📡 Started traffic capture: attack_test/bypass/attack_traffic.pcap
✅ BYPASS attack simulation completed
🎉 All attack simulations completed!
📁 Results saved in attack_test/ directory
```

### 步骤2：运行对比分析

```bash
# 运行对比分析
python3 compare_benign_vs_attack.py
```

**预期输出**：
```
🔍 Analyzing benign activity data...
🔍 Analyzing attack simulation data...
🔄 Comparing benign vs attack characteristics...
📋 Generating comparison report...

================================================================================
🔍 BENIGN vs ATTACK COMPARISON SUMMARY
================================================================================

📊 BENIGN TRAFFIC AVERAGES:
   📦 Average packets per round: 1250
   🔗 Average TCP percentage: 85.2%
   🔌 Average unique ports: 15
   🌐 Average unique IPs: 8

🎯 ATTACK PATTERN ANALYSIS:
   🚀 SLOW_HTTP:
     📦 Packet volume ratio: 0.8x
     🔗 TCP usage difference: +2.1%
   🚀 GET_FLOOD:
     📦 Packet volume ratio: 3.2x
     🔗 TCP usage difference: +5.8%
   🚀 BYPASS:
     📦 Packet volume ratio: 1.1x
     🔗 TCP usage difference: -1.2%

💡 KEY INSIGHTS:
   🚨 GET_FLOOD attack shows 3.2x higher packet volume than benign traffic
   📊 GET_FLOOD attack shows +5.8% difference in TCP usage

🛡️ RECOMMENDATIONS:
   🎯 Attack patterns are distinguishable from benign traffic
   🔍 Consider implementing anomaly detection based on packet volume ratios
   📈 Monitor TCP protocol distribution for unusual patterns
   🛡️ Implement rate limiting based on packet volume thresholds
   🔍 Use machine learning to detect subtle attack patterns
================================================================================
📄 Comparison report saved to benign_vs_attack_comparison.json
```

## 📁 生成的文件结构

```
benignTest/
├── attack_test/
│   ├── slow_http/
│   │   ├── attack_traffic.pcap          # 慢速HTTP攻击流量
│   │   ├── attack_traffic_readable.txt  # 可读格式
│   │   └── worker_*.log                 # 各工作线程日志
│   ├── get_flood/
│   │   ├── attack_traffic.pcap          # GET洪水攻击流量
│   │   ├── attack_traffic_readable.txt  # 可读格式
│   │   └── worker_*.log                 # 各工作线程日志
│   └── bypass/
│       ├── attack_traffic.pcap          # 绕过攻击流量
│       ├── attack_traffic_readable.txt  # 可读格式
│       └── worker_*.log                 # 各工作线程日志
├── benign_vs_attack_comparison.json     # 对比分析报告
└── README_attack_simulation.md          # 本说明文档
```

## ⚙️ 配置选项

### 修改攻击参数

在 `attack_simulation.py` 的 `main()` 函数中：

```python
def main():
    # Configuration
    target_host = "172.16.218.130"  # 目标主机IP
    target_port = "80"              # 目标端口
    attack_duration = 300           # 每次攻击持续时间（秒）
    
    # Create simulator
    simulator = AttackSimulator(target_host, target_port)
    
    # Run attacks
    simulator.run_all_attacks(attack_duration)
```

### 调整攻击强度

在 `AttackSimulator` 类中：

```python
# SLOW HTTP攻击 - 调整并发连接数
for i in range(5):  # 修改这里的数字

# GET洪水攻击 - 调整并发连接数和间隔
for i in range(10):  # 修改并发数
time.sleep(0.1)      # 修改间隔时间

# 绕过攻击 - 调整并发连接数
for i in range(3):   # 修改并发数
```

## 🔍 数据分析要点

### 1. 流量特征对比

- **数据包数量**：攻击流量通常比良性流量高
- **协议分布**：TCP使用比例可能不同
- **端口多样性**：攻击可能使用更多或更少的端口
- **IP多样性**：攻击源IP数量可能异常

### 2. 时间模式分析

- **请求频率**：攻击通常有异常的请求频率
- **连接持续时间**：慢速攻击有长连接，洪水攻击有短连接
- **并发连接数**：攻击通常有更多并发连接

### 3. 行为模式识别

- **User-Agent**：攻击可能使用伪造的User-Agent
- **请求头**：绕过攻击会尝试各种请求头
- **请求路径**：攻击可能访问特定路径

## ⚠️ 注意事项

1. **权限要求**：运行攻击模拟需要sudo权限（用于tcpdump）
2. **网络影响**：攻击模拟可能影响目标服务器性能
3. **数据安全**：确保在测试环境中运行，避免影响生产系统
4. **资源消耗**：长时间运行可能消耗大量系统资源

## 🎓 学术价值

这个攻击模拟系统为你的毕业设计提供了：

1. **真实攻击数据**：模拟真实的网络攻击模式
2. **对比基准**：与良性活动形成鲜明对比
3. **检测验证**：验证你的分析工具的有效性
4. **研究完整性**：完整的安全日志分析研究框架

## 📞 技术支持

如果遇到问题，请检查：

1. **网络连接**：确保能访问目标服务器
2. **权限设置**：确保有sudo权限运行tcpdump
3. **依赖工具**：确保curl和tcpdump已安装
4. **目标服务**：确保目标服务器正在运行

---

**祝你毕业设计顺利！** 🎓✨ 