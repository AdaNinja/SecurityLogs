# CyberRange 评估框架

## 📋 评估目标

根据博士导师建议，本评估分为两个独立的方面：

### 🔄 Group A: 可重复性评估
**目标**: 验证同一场景多次运行的一致性
- **评估问题**: "相同场景3次运行应有相似的恶意/良性事件数量"
- **数据**: 3次无Suricata的baseline实验
- **指标**: 变异系数、攻击类型分布一致性
- **阈值**: CV < 10%

### 🔍 Group B: Suricata影响评估  
**目标**: 验证Suricata不改变攻击行为
- **评估问题**: "有/无Suricata运行产生相似计数，Suricata不阻断流量"
- **数据**: 对比有/无Suricata的实验结果
- **指标**: 攻击事件数量对比、攻击阶段一致性
- **阈值**: 差异 < 10%

## 📁 目录结构

```
evaluation/
├── group_a_reproducibility/     # Group A: 可重复性评估
│   ├── data/baseline_runs/       # 3次baseline实验数据
│   ├── evaluate_group_a.py       # 可重复性分析脚本
│   ├── README.md                 # Group A评估报告
│   └── evaluation_outputs/       # 可重复性分析图表
│
└── group_b_suricata_impact/      # Group B: Suricata影响评估
    ├── data/
    │   ├── without_suricata/      # 无Suricata实验数据
    │   └── with_suricata/         # 有Suricata实验数据
    ├── analysis/                  # Suricata影响分析脚本
    ├── comparison_results/        # 对比分析结果
    ├── validation_outputs/        # 对比分析图表
    └── README.md                  # Group B评估报告
```

## 🎯 评估状态

### Group A (可重复性)
- ✅ 已完成: 3次baseline实验
- ✅ 已完成: 可重复性分析
- ✅ 结果: CV < 1%，优秀的可重复性

### Group B (Suricata影响)  
- ✅ 已完成: 无Suricata数据 (复用Group A)
- 🔄 进行中: 有Suricata实验数据收集
- 📋 待完成: 有/无Suricata对比分析

## 🚀 下一步操作

1. **补充Group B数据**: 运行更多有Suricata的实验
2. **完善对比分析**: 验证Suricata不影响攻击行为  
3. **生成最终报告**: 整合两个评估的结果

## 📊 学术价值

这种双重评估结构完全符合导师的建议：
- Group A证明了实验的可重复性和可靠性
- Group B验证了Suricata集成的透明性和有效性
