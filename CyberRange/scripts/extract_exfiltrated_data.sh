#!/bin/bash

# 数据外传分析脚本
# Script to Extract and Analyze Exfiltrated Data from Advanced Attack

echo "=============================================="
echo "🕵️ 高级攻击数据外传分析工具"
echo "=============================================="

# 设置路径
ANALYSIS_DIR="/home/jiayi/SecurityLogs/CyberRange/analysis/exfiltrated_data"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="$ANALYSIS_DIR/report_$TIMESTAMP"

# 创建报告目录
mkdir -p "$REPORT_DIR"

echo "📁 分析报告目录: $REPORT_DIR"
echo ""

# 获取攻击者容器ID
ATTACKER_CONTAINER=$(docker ps -q --filter name=attacker)

if [ -z "$ATTACKER_CONTAINER" ]; then
    echo "❌ 未找到运行中的攻击者容器"
    echo "请确保已运行高级攻击场景"
    exit 1
fi

echo "🎯 攻击者容器ID: $ATTACKER_CONTAINER"
echo ""

# 1. 提取所有外传相关文件
echo "📤 提取外传数据文件:"
echo "========================"

# 提取外传的敏感数据
echo "正在提取外传数据..."
docker exec $ATTACKER_CONTAINER find /tmp -name "*exfil*" -o -name "*stolen*" -o -name "*data*" 2>/dev/null | while read file; do
    if [ -f "$file" ]; then
        filename=$(basename "$file")
        echo "  ✅ 发现外传文件: $file"
        docker cp $ATTACKER_CONTAINER:$file "$REPORT_DIR/exfil_$filename" 2>/dev/null || echo "  ⚠️ 提取失败"
    fi
done

# 提取shared_data目录中的文件
echo ""
echo "检查共享数据目录..."
docker exec $ATTACKER_CONTAINER ls -la /shared_data 2>/dev/null | while read line; do
    echo "  📂 共享目录: $line"
done

# 复制shared_data中的文件到分析目录
docker exec $ATTACKER_CONTAINER find /shared_data -type f 2>/dev/null | while read file; do
    if [ -f "$file" ]; then
        filename=$(basename "$file")
        echo "  ✅ 发现共享文件: $file"
        docker cp $ATTACKER_CONTAINER:$file "$REPORT_DIR/shared_$filename" 2>/dev/null || echo "  ⚠️ 提取失败"
    fi
done

echo ""

# 2. 提取C2通信记录
echo "📡 提取C2通信记录:"
echo "========================"

# C2注册信息
if docker exec $ATTACKER_CONTAINER test -f /tmp/c2_register.json 2>/dev/null; then
    echo "  ✅ C2注册记录"
    docker cp $ATTACKER_CONTAINER:/tmp/c2_register.json "$REPORT_DIR/c2_registration.json"
else
    echo "  ❌ 未找到C2注册记录"
fi

# C2心跳记录
if docker exec $ATTACKER_CONTAINER test -f /tmp/c2_heartbeat.log 2>/dev/null; then
    echo "  ✅ C2心跳记录"
    docker cp $ATTACKER_CONTAINER:/tmp/c2_heartbeat.log "$REPORT_DIR/c2_heartbeat.log"
    HEARTBEAT_COUNT=$(docker exec $ATTACKER_CONTAINER wc -l /tmp/c2_heartbeat.log 2>/dev/null | awk '{print $1}')
    echo "    └─ 心跳次数: $HEARTBEAT_COUNT"
else
    echo "  ❌ 未找到C2心跳记录"
fi

# 其他C2相关文件
docker exec $ATTACKER_CONTAINER find /tmp -name "c2_*" 2>/dev/null | while read file; do
    filename=$(basename "$file")
    echo "  ✅ 发现C2文件: $file"
    docker cp $ATTACKER_CONTAINER:$file "$REPORT_DIR/$filename" 2>/dev/null
done

echo ""

# 3. 提取攻击成功标志
echo "🏆 提取攻击成功标志:"
echo "========================"

for phase in 1 2 3; do
    if docker exec $ATTACKER_CONTAINER test -f /tmp/phase${phase}_success 2>/dev/null; then
        echo "  ✅ 阶段${phase}成功标志"
        docker cp $ATTACKER_CONTAINER:/tmp/phase${phase}_success "$REPORT_DIR/phase${phase}_success.txt"
        SUCCESS_DATA=$(docker exec $ATTACKER_CONTAINER cat /tmp/phase${phase}_success 2>/dev/null)
        echo "    └─ 数据: $SUCCESS_DATA"
    else
        echo "  ❌ 阶段${phase}未成功"
    fi
done

echo ""

# 4. 提取攻击日志
echo "📋 提取攻击日志:"
echo "========================"

if docker exec $ATTACKER_CONTAINER test -f /logs/advanced_attack.log 2>/dev/null; then
    echo "  ✅ 高级攻击日志"
    docker cp $ATTACKER_CONTAINER:/logs/advanced_attack.log "$REPORT_DIR/advanced_attack.log"
else
    echo "  ❌ 未找到高级攻击日志"
fi

if docker exec $ATTACKER_CONTAINER test -f /logs/advanced_attack_report.json 2>/dev/null; then
    echo "  ✅ 攻击报告"
    docker cp $ATTACKER_CONTAINER:/logs/advanced_attack_report.json "$REPORT_DIR/attack_report.json"
else
    echo "  ❌ 未找到攻击报告"
fi

echo ""

# 5. 分析外传数据内容
echo "🔍 分析外传数据内容:"
echo "========================"

cd "$REPORT_DIR"

# 分析JSON文件
if ls *.json >/dev/null 2>&1; then
    echo "📄 JSON文件分析:"
    for json_file in *.json; do
        echo "  📝 $json_file:"
        if command -v jq >/dev/null 2>&1; then
            jq . "$json_file" 2>/dev/null | head -10
        else
            cat "$json_file" | head -5
        fi
        echo ""
    done
fi

# 分析日志文件
if ls *.log >/dev/null 2>&1; then
    echo "📄 日志文件分析:"
    for log_file in *.log; do
        echo "  📝 $log_file (前10行):"
        head -10 "$log_file"
        echo "  📊 总行数: $(wc -l < "$log_file")"
        echo ""
    done
fi

# 分析文本文件
if ls *.txt >/dev/null 2>&1; then
    echo "📄 文本文件分析:"
    for txt_file in *.txt; do
        echo "  📝 $txt_file:"
        cat "$txt_file"
        echo ""
    done
fi

# 分析所有其他文件
echo "📄 其他文件分析:"
for file in *; do
    if [ -f "$file" ] && [[ ! "$file" =~ \.(json|log|txt)$ ]]; then
        echo "  📝 $file:"
        echo "    └─ 文件大小: $(du -h "$file" | awk '{print $1}')"
        echo "    └─ 文件类型: $(file "$file" | cut -d: -f2-)"
        echo "    └─ 内容预览:"
        head -5 "$file" 2>/dev/null | sed 's/^/      /'
        echo ""
    fi
done

# 6. 生成分析报告
echo "📊 生成分析报告:"
echo "========================"

REPORT_FILE="$REPORT_DIR/exfiltration_analysis_report.md"

cat > "$REPORT_FILE" << EOF
# 高级攻击数据外传分析报告

**生成时间**: $(date)
**攻击者容器**: $ATTACKER_CONTAINER
**分析目录**: $REPORT_DIR

## 📤 外传数据统计

**文件总数**: $(find . -type f | wc -l)
**数据总大小**: $(du -sh . | awk '{print $1}')

### 文件清单
$(ls -la)

## 🎯 攻击阶段成功情况

EOF

# 检查各阶段成功情况
for phase in 1 2 3; do
    if [ -f "phase${phase}_success.txt" ]; then
        echo "- ✅ 阶段${phase}: 成功 - $(cat phase${phase}_success.txt)" >> "$REPORT_FILE"
    else
        echo "- ❌ 阶段${phase}: 失败" >> "$REPORT_FILE"
    fi
done

cat >> "$REPORT_FILE" << EOF

## 📡 C2通信分析

EOF

if [ -f "c2_registration.json" ]; then
    echo "### C2注册信息" >> "$REPORT_FILE"
    echo '```json' >> "$REPORT_FILE"
    cat c2_registration.json >> "$REPORT_FILE"
    echo '```' >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

if [ -f "c2_heartbeat.log" ]; then
    echo "### C2心跳通信" >> "$REPORT_FILE"
    echo "心跳次数: $(wc -l < c2_heartbeat.log)" >> "$REPORT_FILE"
    echo '```json' >> "$REPORT_FILE"
    head -3 c2_heartbeat.log >> "$REPORT_FILE"
    echo '```' >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
fi

cat >> "$REPORT_FILE" << EOF

## 🔍 外传数据内容

EOF

# 添加文件内容到报告
for file in exfil_* shared_*; do
    if [ -f "$file" ]; then
        echo "### $file" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        head -10 "$file" >> "$REPORT_FILE"
        echo '```' >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
done

echo "✅ 分析报告已生成: $REPORT_FILE"
echo ""

# 7. 显示总结
echo "📋 外传数据分析总结:"
echo "========================"
echo "📁 分析目录: $REPORT_DIR"
echo "📊 提取文件数: $(find "$REPORT_DIR" -type f | wc -l)"
echo "💾 数据总大小: $(du -sh "$REPORT_DIR" | awk '{print $1}')"
echo "📄 分析报告: $REPORT_FILE"
echo ""
echo "🔍 查看完整报告:"
echo "cat $REPORT_FILE"
echo ""
echo "🗂️ 浏览提取的文件:"
echo "ls -la $REPORT_DIR"
echo ""
echo "=============================================="
echo "🏁 数据外传分析完成"
echo "=============================================="
