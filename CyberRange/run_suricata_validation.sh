#!/bin/bash
set -e

# Suricata补充性检查脚本
# 运行3次无Suricata + 1次有Suricata的test_all_features场景

SCENARIO_NO_SURI="scenarios/test_all_features.yaml"
SCENARIO_WITH_SURI="scenarios/test_all_features_with_suricata.yaml"
BASE_RUNS_DIR="/mnt/mypassport/cyberrange_data/runs"
VALIDATION_DIR="$BASE_RUNS_DIR/suricata_validation"
CURRENT_RUN_SYMLINK="$BASE_RUNS_DIR/current_run"
MAIN_LOG_FILE="$BASE_RUNS_DIR/suricata_validation.log"

# 创建验证目录
mkdir -p "$VALIDATION_DIR"
mkdir -p "$VALIDATION_DIR/no_suri"
mkdir -p "$VALIDATION_DIR/with_suri"

echo "[$(date +'%Y-%m-%d %H:%M:%S')] === 开始Suricata补充性检查 ===" | tee -a "$MAIN_LOG_FILE"
echo "[$(date +'%Y-%m-%d %H:%M:%S')] PID: $$" | tee -a "$MAIN_LOG_FILE"

# 清理函数
cleanup() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] 清理Docker容器..." | tee -a "$MAIN_LOG_FILE"
    docker rm -f $(docker ps -aq) 2>/dev/null || true
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] 清理完成" | tee -a "$MAIN_LOG_FILE"
}

# 运行无Suricata实验
run_no_suri_experiment() {
    local run_num=$1
    local run_dir="$VALIDATION_DIR/no_suri/run_$run_num"
    
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] 开始无Suricata实验 #$run_num" | tee -a "$MAIN_LOG_FILE"
    
    # 创建运行目录
    mkdir -p "$run_dir"
    rm -f "$CURRENT_RUN_SYMLINK"
    ln -sfn "$run_dir" "$CURRENT_RUN_SYMLINK"
    
    # 运行实验
    python3 run_scenario.py --config "$SCENARIO_NO_SURI" >> "$MAIN_LOG_FILE" 2>&1
    
    # 解析日志
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] 解析日志..." | tee -a "$MAIN_LOG_FILE"
    python3 parsers/parse_logs.py \
        --input-dir "$run_dir/logs/test-all-features_$(date +%Y%m%d_%H%M%S)" \
        --output-dir "$run_dir/output/" \
        --log-type all >> "$MAIN_LOG_FILE" 2>&1
    
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] 无Suricata实验 #$run_num 完成" | tee -a "$MAIN_LOG_FILE"
}

# 运行有Suricata实验
run_with_suri_experiment() {
    local run_num=$1
    local run_dir="$VALIDATION_DIR/with_suri/run_$run_num"
    
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] 开始有Suricata实验 #$run_num" | tee -a "$MAIN_LOG_FILE"
    
    # 创建运行目录
    mkdir -p "$run_dir"
    rm -f "$CURRENT_RUN_SYMLINK"
    ln -sfn "$run_dir" "$CURRENT_RUN_SYMLINK"
    
    # 运行实验
    python3 run_scenario.py --config "$SCENARIO_WITH_SURI" >> "$MAIN_LOG_FILE" 2>&1
    
    # 解析日志
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] 解析日志..." | tee -a "$MAIN_LOG_FILE"
    python3 parsers/parse_logs.py \
        --input-dir "$run_dir/logs/test-all-features-with-suricata_$(date +%Y%m%d_%H%M%S)" \
        --output-dir "$run_dir/output/" \
        --log-type all >> "$MAIN_LOG_FILE" 2>&1
    
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] 有Suricata实验 #$run_num 完成" | tee -a "$MAIN_LOG_FILE"
}

# 主执行流程
echo "[$(date +'%Y-%m-%d %H:%M:%S')] 系统状态检查:" | tee -a "$MAIN_LOG_FILE"
df -h | tee -a "$MAIN_LOG_FILE"
free -h | tee -a "$MAIN_LOG_FILE"

# 运行3次无Suricata实验
for i in {1..3}; do
    cleanup
    run_no_suri_experiment "$i"
    sleep 10  # 短暂休息
done

# 运行1次有Suricata实验
cleanup
run_with_suri_experiment "1"

# 最终清理
cleanup

echo "[$(date +'%Y-%m-%d %H:%M:%S')] === Suricata补充性检查完成 ===" | tee -a "$MAIN_LOG_FILE"
echo "[$(date +'%Y-%m-%d %H:%M:%S')] 数据位置: $VALIDATION_DIR" | tee -a "$MAIN_LOG_FILE"
