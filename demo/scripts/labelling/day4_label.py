#!/usr/bin/env python3
import re
import csv
from datetime import datetime

# 配置
INPUT_CSV = "demo/data/raw/windows_security_full.csv"
INITIAL_PIDS_FILE = "labelling/initial_pids.txt"
OUTPUT_CSV = "labelling/labelled_events.csv"

# 1. 读初始恶意 PID
with open(INITIAL_PIDS_FILE) as f:
    malicious = set(line.strip() for line in f if line.strip())

# 2. 正则
re_pid   = re.compile(r"New Process ID:\s*0x([0-9a-fA-F]+)")
re_ppid  = re.compile(r"Creator Process ID:\s*0x([0-9a-fA-F]+)")

# 3. 准备输出
with open(OUTPUT_CSV, "w", newline='') as fout:
    writer = csv.writer(fout)
    writer.writerow(["event_id","timestamp","pid","ppid","attack_id","label"])

    # 4. 逐行扫描
    with open(INPUT_CSV) as fin:
        reader = csv.DictReader(fin)
        event_id = 1
        for row in reader:
            if row["Id"] != "4688":
                continue
            msg = row["Message"]
            m1 = re_pid.search(msg)
            m2 = re_ppid.search(msg)
            if not m1 or not m2:
                continue  # 跳过无法解析的行
            pid  = int(m1.group(1),16)
            ppid = int(m2.group(1),16)

            # 5. 标记逻辑
            label = "benign"
            if str(pid) in malicious:
                label = "attack"
            elif str(ppid) in malicious:
                label = "attack"
                malicious.add(str(pid))

            ts = row["TimeCreated"]
            atk = "A1"
            writer.writerow([event_id, ts, pid, ppid, atk, label])
            event_id += 1

# 6. 记录决策日志
with open("labelling/decision_log.md","a") as log:
    log.write(f"\n## Run day4_label.py\n")
    log.write(f"- Timestamp: {datetime.now().isoformat()}\n")
    log.write(f"- Initial PIDs: {','.join(sorted(malicious))}\n")
    log.write(f"- Output: {OUTPUT_CSV}\n")
