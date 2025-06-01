# import os
# import glob
# import json
# import zipfile
# from datetime import datetime
# import random

# # Directory where demo data lives (adjust path if needed)
# DEMO_DIR = os.path.expanduser("~/security-demo/demo")
# OUTPUT_ZIP = os.path.join(DEMO_DIR, "raw_dataset.zip")
# META_FILE = os.path.join(DEMO_DIR, "run_meta.json")

# def collect_and_archive():
#     # Generate a reproducible random seed
#     seed = random.randint(0, 2**32 - 1)
#     random.seed(seed)
    
#     # Find files to include in the archive
#     patterns = ["*.evtx", "*.csv", "*.pcap", "*.log"]
#     files = []
#     for pat in patterns:
#         files.extend(glob.glob(os.path.join(DEMO_DIR, pat)))
    
#     # Ensure the demo directory exists
#     if not os.path.isdir(DEMO_DIR):
#         print(f"Error: Demo directory not found: {DEMO_DIR}")
#         return
    
#     # Create the ZIP archive
#     with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
#         for filepath in files:
#             arcname = os.path.basename(filepath)
#             zf.write(filepath, arcname)
    
#     # Build metadata
#     metadata = {
#         "run_timestamp": datetime.utcnow().isoformat() + "Z",
#         "random_seed": seed,
#         "files_included": [os.path.basename(f) for f in files]
#     }
#     with open(META_FILE, "w") as f:
#         json.dump(metadata, f, indent=2)
    
#     print(f"Archived {len(files)} files to {OUTPUT_ZIP}")
#     print(f"Metadata written to {META_FILE}")

# if __name__ == "__main__":
#     collect_and_archive()


import os
import glob
import json
import zipfile
from datetime import datetime
import random

# 基础目录
BASE_DIR = os.path.expanduser("~/security-demo/demo")
DATA_DIR = os.path.join(BASE_DIR, "data")
RAW_DIR = os.path.join(DATA_DIR, "raw")
META_DIR = os.path.join(DATA_DIR, "metadata")

# 确保目录存在
for directory in [RAW_DIR, META_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory)

# 输出文件
OUTPUT_ZIP = os.path.join(DATA_DIR, "all_vms_data.zip")
META_FILE = os.path.join(META_DIR, "all_vms_meta.json")

# 要收集的文件模式
PATTERNS = ["*.evtx", "*.xml", "*.csv", "*.pcap", "*.log"]

# 数据源标识
DATA_SOURCES = {
    "windows_vm": {
        "patterns": ["windows", "win", "system", "security", "application", "sysmon"],
        "file_types": ["evtx", "xml"]
    },
    "kali_victim1": {
        "patterns": ["victim1"],
        "file_types": ["pcap"],
        "exact_matches": ["victim1.pcap"]  # 精确匹配
    },
    "kali_victim2": {
        "patterns": ["victim2"],
        "file_types": ["pcap"],
        "exact_matches": ["victim2.pcap"]  # 精确匹配
    }
}

def identify_data_source(filename):
    """
    识别文件的数据源
    :param filename: 文件名
    :return: 数据源名称
    """
    filename_lower = filename.lower()
    
    # 首先检查精确匹配
    for source, config in DATA_SOURCES.items():
        if "exact_matches" in config and filename in config["exact_matches"]:
            return source
    
    # 然后检查文件名模式
    for source, config in DATA_SOURCES.items():
        # 检查文件名是否包含数据源标识
        if any(pattern in filename_lower for pattern in config["patterns"]):
            return source
        # 检查文件类型是否匹配
        if any(filename_lower.endswith(ft) for ft in config["file_types"]):
            return source
    return "unknown"

def collect_and_archive():
    # 生成随机种子
    seed = random.randint(0, 2**32 - 1)
    random.seed(seed)
    
    # 确保目录存在
    if not os.path.isdir(RAW_DIR):
        print(f"Error: Raw data directory not found: {RAW_DIR}")
        return
    if not os.path.isdir(META_DIR):
        print(f"Error: Metadata directory not found: {META_DIR}")
        return

    # 查找要包含在归档中的文件
    files = []
    for pat in PATTERNS:
        pattern_path = os.path.join(RAW_DIR, pat)
        found = glob.glob(pattern_path)
        if found:
            print(f"Found {len(found)} files matching pattern {pat}")
            for f in found:
                print(f"  - {os.path.basename(f)}")
        files.extend(found)
    files = sorted(set(files))  # 去重并排序
    
    if not files:
        print(f"Warning: No files found in {RAW_DIR} matching patterns: {PATTERNS}")
        return
    
    # 创建ZIP归档
    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
        for filepath in files:
            arcname = os.path.basename(filepath)
            zf.write(filepath, arcname)
    
    # 按数据源分类文件
    files_by_source = {source: [] for source in DATA_SOURCES.keys()}
    files_by_source["unknown"] = []
    
    for filepath in files:
        filename = os.path.basename(filepath)
        source = identify_data_source(filename)
        files_by_source[source].append(filename)
    
    # 构建元数据
    metadata = {
        "run_timestamp": datetime.utcnow().isoformat() + "Z",
        "random_seed": seed,
        "files_included": [os.path.basename(f) for f in files],
        "data_sources": files_by_source
    }
    
    # 保存元数据
    with open(META_FILE, "w") as f:
        json.dump(metadata, f, indent=2)
    
    print(f"\nSummary:")
    print(f"Archived {len(files)} files to {OUTPUT_ZIP}")
    print(f"Metadata written to {META_FILE}")
    print("\nFiles by source:")
    for source, source_files in files_by_source.items():
        print(f"{source}: {len(source_files)} files")
        if source_files:
            print("  Files:")
            for f in source_files:
                print(f"    - {f}")

if __name__ == "__main__":
    collect_and_archive()
