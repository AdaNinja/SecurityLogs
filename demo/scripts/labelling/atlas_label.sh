# Decision-ID: atlas_v1_$(git rev-parse --short HEAD)
# Date: $(date -Iseconds)

# 简易 PID 传播打标脚本（Day 4 原型）
# 依赖：initial_pids.txt, windows_security_full.csv
# 输出：labelled_events.csv

# 配置路径
INITIAL_PIDS="labelling/initial_pids.txt"
INPUT_CSV="demo/data/raw/windows_security_full.csv"
OUTPUT_CSV="labelling/labelled_events.csv"

# 读取初始恶意 PID
declare -A malicious_pids
while IFS= read -r pid; do
  malicious_pids["$pid"]=1
done < "$INITIAL_PIDS"

# 准备输出文件，写入表头
echo "event_id,timestamp,provider,pid,ppid,attack_id,label" > "$OUTPUT_CSV"

# 跳过 CSV header，从第2行开始处理
tail -n +2 "$INPUT_CSV" | nl -v 2 -w1 -s',' | while IFS=',' read -r event_id TimeCreated ProviderName RecordId Message; do
  # 假设 CSV 有 pid 和 ppid 两列，需要按实际列索引调整
  # 例如 pid 在第6列，ppid 在第7列，此处用 awk 取示例
  pid=$(echo "$Message" | awk -F'PID=' '{print $2}' | awk '{print $1}')
  ppid=$(echo "$Message" | awk -F'PPID=' '{print $2}' | awk '{print $1}')

  label="benign"
  attack_id="A1"
  if [[ -n "${malicious_pids[$pid]}" ]]; then
    label="attack"
  elif [[ -n "${malicious_pids[$ppid]}" ]]; then
    malicious_pids["$pid"]=1
    label="attack"
  fi

  # 输出结果
  echo "$event_id,$TimeCreated,$ProviderName,$pid,$ppid,$attack_id,$label" >> "$OUTPUT_CSV"
done

# 记录到决策日志
cat <<EOF >> labelling/decision_log.md

## Run atlas_label.sh
- Decision-ID: atlas_v1_$(git rev-parse --short HEAD)
- Date: $(date -Iseconds)
- Output: labelled_events.csv
EOF
