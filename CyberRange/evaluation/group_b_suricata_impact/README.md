# Group B: Suricata影响评估

## 🎯 评估目标

验证Suricata作为被动监控器，不改变恶意行为，产生相似的攻击事件计数。

## 📊 评估方法

### 对比实验设计
1. **Control组**: 无Suricata的实验 (复用Group A数据)
2. **Treatment组**: 有Suricata的实验
3. **对比指标**: 
   - 攻击事件总数
   - 攻击类型分布
   - 攻击时序模式
   - 攻击成功率

### 验证标准
- **数量一致性**: 有/无Suricata的攻击数量差异 < 10%
- **行为保持**: 攻击类型分布保持一致
- **阶段符合**: 所有运行符合相同攻击阶段
- **监控有效**: Suricata生成相关告警

## 📁 数据组织

```
data/
├── without_suricata/    # Control组: A_no_suri数据
│   ├── run_01/         # 基线实验1
│   ├── run_02/         # 基线实验2  
│   └── run_03/         # 基线实验3
└── with_suricata/      # Treatment组: 有Suricata数据
    ├── run_01/         # Suricata实验1
    ├── run_02/         # Suricata实验2 (待补充)
    └── run_03/         # Suricata实验3 (待补充)
```

## 🔬 分析脚本

- `analysis/validate_suricata_impact.py`: 主要对比分析
- `analysis/final_comparison.py`: 最终验证报告
- `analysis/simple_validation.py`: 快速状态检查

## 📈 当前状态

- ✅ Control组数据: 3次实验完整
- 🔄 Treatment组数据: 1次实验完成，需补充2次
- 📋 对比分析: 初步完成，待最终验证

## 🚀 补充实验

运行更多有Suricata的实验:
```bash
cd /home/jiayi/SecurityLogs/CyberRange
./run_group_b_supplement.sh --runs 2
```
