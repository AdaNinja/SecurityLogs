#!/bin/bash

# 高级三阶段攻击成功检查脚本
# Advanced Three-Phase Attack Success Checker

echo "=============================================="
echo "🔍 检查高级三阶段攻击执行结果"
echo "=============================================="

LOGS_DIR="/home/jiayi/SecurityLogs/CyberRange/logs"
SCENARIO_NAME="advanced-attack-three-phase"

# 查找最新的日志目录
LATEST_LOG_DIR=$(find "$LOGS_DIR" -type d -name "*${SCENARIO_NAME}*" | sort | tail -1)

if [ -z "$LATEST_LOG_DIR" ]; then
    echo "❌ 未找到高级攻击场景的日志目录"
    echo "请确保已运行: python3 run_scenario.py scenarios/advanced_attack_three_phase.yaml"
    exit 1
fi

echo "📁 日志目录: $LATEST_LOG_DIR"
echo ""

# 检查攻击者容器内的成功标志文件
echo "🎯 阶段成功检查:"
echo "===================="

# 阶段1：Shell获取
echo -n "阶段1 (Shell获取): "
if docker exec $(docker ps -q --filter name=attacker) test -f /tmp/phase1_success 2>/dev/null; then
    echo "✅ 成功"
    PHASE1_DATA=$(docker exec $(docker ps -q --filter name=attacker) cat /tmp/phase1_success 2>/dev/null)
    echo "  └─ 数据: $PHASE1_DATA"
else
    echo "❌ 失败或未执行"
fi

# 阶段2：C2通信
echo -n "阶段2 (C2通信): "
if docker exec $(docker ps -q --filter name=attacker) test -f /tmp/phase2_success 2>/dev/null; then
    echo "✅ 成功"
    PHASE2_DATA=$(docker exec $(docker ps -q --filter name=attacker) cat /tmp/phase2_success 2>/dev/null)
    echo "  └─ 受害者ID: $PHASE2_DATA"
    
    # 检查C2通信日志
    if docker exec $(docker ps -q --filter name=attacker) test -f /tmp/c2_heartbeat.log 2>/dev/null; then
        HEARTBEAT_COUNT=$(docker exec $(docker ps -q --filter name=attacker) wc -l /tmp/c2_heartbeat.log 2>/dev/null | awk '{print $1}')
        echo "  └─ 心跳次数: $HEARTBEAT_COUNT"
    fi
else
    echo "❌ 失败或未执行"
fi

# 阶段3：数据外传
echo -n "阶段3 (数据外传): "
if docker exec $(docker ps -q --filter name=attacker) test -f /tmp/phase3_success 2>/dev/null; then
    echo "✅ 成功"
    PHASE3_DATA=$(docker exec $(docker ps -q --filter name=attacker) cat /tmp/phase3_success 2>/dev/null)
    echo "  └─ 数据: $PHASE3_DATA"
    
    # 检查外传的数据文件
    if docker exec $(docker ps -q --filter name=attacker) test -f /tmp/exfil_data.txt 2>/dev/null; then
        EXFIL_SIZE=$(docker exec $(docker ps -q --filter name=attacker) wc -c /tmp/exfil_data.txt 2>/dev/null | awk '{print $1}')
        echo "  └─ 外传数据大小: $EXFIL_SIZE bytes"
    fi
else
    echo "❌ 失败或未执行"
fi

echo ""

# 检查攻击报告
echo "📊 攻击报告检查:"
echo "=================="
if docker exec $(docker ps -q --filter name=attacker) test -f /logs/advanced_attack_report.json 2>/dev/null; then
    echo "✅ 攻击报告已生成"
    docker exec $(docker ps -q --filter name=attacker) cat /logs/advanced_attack_report.json 2>/dev/null | python3 -m json.tool
else
    echo "❌ 攻击报告未生成"
fi

echo ""

# 检查详细日志
echo "📋 详细日志检查:"
echo "=================="
ATTACK_LOG="$LATEST_LOG_DIR/attacker/advanced_attack.log"

if [ -f "$ATTACK_LOG" ]; then
    echo "✅ 攻击日志文件存在"
    
    # 统计各阶段日志
    PHASE1_LOGS=$(grep '"phase":"1"' "$ATTACK_LOG" | wc -l)
    PHASE2_LOGS=$(grep '"phase":"2"' "$ATTACK_LOG" | wc -l)
    PHASE3_LOGS=$(grep '"phase":"3"' "$ATTACK_LOG" | wc -l)
    
    echo "  └─ 阶段1日志条数: $PHASE1_LOGS"
    echo "  └─ 阶段2日志条数: $PHASE2_LOGS"
    echo "  └─ 阶段3日志条数: $PHASE3_LOGS"
    
    # 显示最后几条成功日志
    echo ""
    echo "🎯 最近的成功事件:"
    grep -i "success\|成功\|completed" "$ATTACK_LOG" | tail -3 | while read line; do
        echo "  └─ $line"
    done
else
    echo "❌ 攻击日志文件不存在: $ATTACK_LOG"
fi

echo ""

# 网络流量检查
echo "🌐 网络流量检查:"
echo "=================="
PCAP_FILE="$LATEST_LOG_DIR/advanced_attack_network_traffic.pcap"

if [ -f "$PCAP_FILE" ]; then
    echo "✅ 网络流量文件存在"
    PCAP_SIZE=$(du -h "$PCAP_FILE" | awk '{print $1}')
    echo "  └─ 文件大小: $PCAP_SIZE"
    
    # 检查是否有tshark来分析pcap
    if command -v tshark >/dev/null 2>&1; then
        PACKET_COUNT=$(tshark -r "$PCAP_FILE" -T fields -e frame.number | tail -1 2>/dev/null)
        echo "  └─ 数据包数量: $PACKET_COUNT"
        
        # 检查HTTP POST请求（攻击流量）
        HTTP_POSTS=$(tshark -r "$PCAP_FILE" -Y "http.request.method==POST" -T fields -e frame.number | wc -l 2>/dev/null)
        echo "  └─ HTTP POST请求: $HTTP_POSTS (可能的攻击流量)"
    fi
else
    echo "❌ 网络流量文件不存在"
fi

echo ""
echo "=============================================="
echo "🏁 检查完成"
echo "=============================================="
