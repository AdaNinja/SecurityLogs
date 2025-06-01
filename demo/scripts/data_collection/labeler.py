# 从 data/raw/ 目录中读取所有主机的 CSV 日志
# 根据 ground-truth（初始恶意 PID / IP）自动标记所有事件的 L1
# 递归传播：任何子进程或后续流量也打为恶意
# 输出 security-demo/data/labeled/labels_L1.csv

#!/usr/bin/env python3
import os, json, csv

# --- constants ---
BASE = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
RAW_DIR = os.path.join(BASE, "data/raw")
OUT_DIR = os.path.join(BASE, "data/labeled")
os.makedirs(OUT_DIR, exist_ok=True)

CFG = os.path.join(BASE, "scenarios/scenario1/config.json")
OUT_CSV = os.path.join(OUT_DIR, "labels_L1.csv")

# --- load ground-truth ---
with open(CFG) as f:
    cfg = json.load(f)
mal_pids = set(cfg["initial_malicious_pids"])
mal_ips  = set(cfg["malicious_ips"])
seen_pids = set(mal_pids)

# --- label function ---
def process_host(host, csv_name, writer):
    path = os.path.join(RAW_DIR, csv_name)
    if not os.path.isfile(path): return
    with open(path, newline="", encoding="utf-8") as f:
        rd = csv.DictReader(f)
        for r in rd:
            rec = r.get("EventRecordID") or r.get("record_id","")
            pid = int(r.get("ProcessId", r.get("pid","0")) or 0)
            ppid= int(r.get("ParentProcessId","0") or 0)
            sip = r.get("SourceIp", r.get("src_ip",""))
            dip = r.get("DestIp",   r.get("dst_ip",""))
            # L1 判定
            if pid in seen_pids or ppid in seen_pids or sip in mal_ips or dip in mal_ips:
                label = 1
                seen_pids.add(pid)
            else:
                label = 0
            writer.writerow([rec, host, pid, ppid, sip, dip, label])

# --- main ---
with open(OUT_CSV, "w", newline="", encoding="utf-8") as out:
    w = csv.writer(out)
    w.writerow(["RecordID","Host","ProcessId","ParentProcessId","SrcIp","DstIp","L1"])
    for h, fname in cfg["host_csv"].items():
        process_host(h, fname, w)

print(f"[Day4] L1 labels written to {OUT_CSV}")
