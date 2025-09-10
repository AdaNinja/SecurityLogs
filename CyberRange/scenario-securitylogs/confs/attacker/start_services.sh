#!/bin/bash
"""
Attacker Container Service Startup Script
启动攻击者容器的各种服务
"""

echo "=== Starting Attacker Container Services ==="

# 获取实验名称和时间戳
EXPERIMENT_NAME=${EXPERIMENT_NAME:-"default_experiment"}
TIMESTAMP=${TIMESTAMP:-$(date +%Y%m%d_%H%M%S)}
FULL_EXPERIMENT_NAME="${EXPERIMENT_NAME}_${TIMESTAMP}"

echo "Starting services for experiment: $EXPERIMENT_NAME"
echo "Full experiment name: $FULL_EXPERIMENT_NAME"

# 创建必要的目录（按实验名称组织）
echo "Creating experiment directories..."
mkdir -p /logs 
mkdir -p "/shared_data/$FULL_EXPERIMENT_NAME"
mkdir -p "/exfiltrated_data/$FULL_EXPERIMENT_NAME"

# 检查并整理现有的未分类数据
echo "Organizing existing data..."

# 整理shared_data中的根目录文件
if [ -d "/shared_data" ]; then
    # 移动根目录下的文件到实验目录
    moved_files=0
    for file in /shared_data/*; do
        if [ -f "$file" ]; then
            filename=$(basename "$file")
            mv "$file" "/shared_data/$FULL_EXPERIMENT_NAME/$filename" 2>/dev/null && {
                echo "📁 Moved $filename to experiment directory"
                ((moved_files++))
            }
        fi
    done
    [ $moved_files -gt 0 ] && echo "✅ Organized $moved_files files in shared_data"
fi

# 整理exfiltrated_data中的根目录文件
if [ -d "/exfiltrated_data" ]; then
    # 移动根目录下的文件到实验目录
    moved_files=0
    for file in /exfiltrated_data/*; do
        if [ -f "$file" ]; then
            filename=$(basename "$file")
            mv "$file" "/exfiltrated_data/$FULL_EXPERIMENT_NAME/$filename" 2>/dev/null && {
                echo "📁 Moved $filename to experiment directory"
                ((moved_files++))
            }
        fi
    done
    [ $moved_files -gt 0 ] && echo "✅ Organized $moved_files files in exfiltrated_data"
fi

# 更新环境变量供其他脚本使用
export EXPERIMENT_NAME
export FULL_EXPERIMENT_NAME
export TIMESTAMP

# 启动数据接收服务器
echo "Starting data exfiltration receiver server..."
python3 /common_scripts/data_receiver.py &
DATA_RECEIVER_PID=$!

# 等待服务器启动
sleep 3

# 检查服务器是否正常启动
if curl -s http://localhost:8080/status > /dev/null; then
    echo "✅ Data receiver server started successfully on port 8080"
else
    echo "❌ Failed to start data receiver server"
fi

# 启动简单的文件服务器（用于C2通信）
echo "Starting file server for C2 communication..."
cd "/shared_data/$FULL_EXPERIMENT_NAME"
python3 -m http.server 8443 &
FILE_SERVER_PID=$!

echo "✅ File server started on port 8443"

# 创建服务状态文件
cat > /tmp/services_status.json << EOF
{
    "data_receiver": {
        "pid": $DATA_RECEIVER_PID,
        "port": 8080,
        "status": "running"
    },
    "file_server": {
        "pid": $FILE_SERVER_PID,
        "port": 8443,
        "status": "running"
    },
    "started_at": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
}
EOF

echo "=== Attacker Services Started ==="
echo "Experiment: $EXPERIMENT_NAME"
echo "Full Experiment Name: $FULL_EXPERIMENT_NAME"
echo "Data Receiver: http://localhost:8080"
echo "File Server: http://localhost:8443"
echo "Logs: /logs/"
echo "Exfiltrated Data: /exfiltrated_data/$FULL_EXPERIMENT_NAME/"
echo "Shared Data: /shared_data/$FULL_EXPERIMENT_NAME/"

# 保持脚本运行
wait
