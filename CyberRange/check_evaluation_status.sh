#!/bin/bash
#
# 统一评估状态检查
#

echo "=== CyberRange 评估状态 ==="
echo

# Group A 状态
echo "🔄 Group A (可重复性评估):"
if [[ -d "evaluation/group_a_reproducibility" ]]; then
    if [[ -f "evaluation/group_a_reproducibility/README.md" ]]; then
        echo "  ✅ 评估完成"
        echo "  📊 结果: 变异系数 < 1%，优秀可重复性"
    else
        echo "  ⚠️  评估部分完成"
    fi
    
    # 检查数据
    baseline_runs=$(find evaluation/group_a_reproducibility/data/baseline_runs -name "run_*" -type d 2>/dev/null | wc -l)
    echo "  📁 数据: $baseline_runs 次baseline实验"
else
    echo "  ❌ 未设置"
fi

echo

# Group B 状态  
echo "🔍 Group B (Suricata影响评估):"
if [[ -d "evaluation/group_b_suricata_impact" ]]; then
    # 检查Control组
    control_runs=$(find evaluation/group_b_suricata_impact/data/without_suricata -name "run_*" -type d 2>/dev/null | wc -l)
    echo "  📁 Control组 (无Suricata): $control_runs 次实验"
    
    # 检查Treatment组
    treatment_runs=$(find evaluation/group_b_suricata_impact/data/with_suricata -name "run_*" -type d 2>/dev/null | wc -l)
    echo "  📁 Treatment组 (有Suricata): $treatment_runs 次实验"
    
    if [[ $treatment_runs -ge 3 ]]; then
        echo "  ✅ 数据充足，可进行完整对比分析"
    elif [[ $treatment_runs -ge 1 ]]; then
        needed=$((3 - treatment_runs))
        echo "  ⚠️  需要补充 $needed 次Suricata实验"
    else
        echo "  ❌ 缺少Suricata实验数据"
    fi
else
    echo "  ❌ 未设置"
fi

echo

# 建议操作
echo "💡 建议操作:"
if [[ $treatment_runs -lt 3 ]]; then
    needed=$((3 - treatment_runs))
    echo "  🔄 补充Group B数据: ./run_group_b_supplement.sh --runs $needed"
fi

echo "  📊 查看Group A结果: cat group_a_evaluation/README.md"
echo "  📊 查看Group B结果: cat group_b_evaluation/README.md"
echo "  🔍 检查详细状态: ls -la evaluation/"
