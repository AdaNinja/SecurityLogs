#!/usr/bin/env python3
"""
Data Collection Script
Collect and organize security log data from various sources
"""

import os
import sys
import json
import shutil
import random
from pathlib import Path
from typing import Dict, List, Any

def collect_data(source_dir: str, output_dir: str, config_file: str = None):
    """
    Collect data from source directory and organize it into output directory
    
    Args:
        source_dir: Source directory containing raw data
        output_dir: Output directory for organized data
        config_file: Configuration file path (optional)
    """
    
    # Load configuration
    if config_file and os.path.exists(config_file):
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
    else:
        config = get_default_config()
    
    # Base directory
    base_dir = Path(output_dir)
    
    # Ensure directory exists
    base_dir.mkdir(parents=True, exist_ok=True)
    
    # Output file
    output_file = base_dir / "data_collection_summary.json"
    
    # File patterns to collect
    file_patterns = config.get("file_patterns", {})
    
    # Data source identifiers
    data_sources = {
        "victim1": {
            "patterns": ["victim1", "vm1"],
            "exact_matches": ["victim1.pcap"]  # Exact matches
        },
        "victim2": {
            "patterns": ["victim2", "vm2"],
            "exact_matches": ["victim2.pcap"]  # Exact matches
        }
    }
    
    def identify_data_source(filename: str) -> str:
        """
        Identify data source from filename
        :param filename: Filename
        :return: Data source name
        """
        # First check exact matches
        for source, patterns in data_sources.items():
            if filename in patterns.get("exact_matches", []):
                return source
        
        # Then check filename patterns
        for source, patterns in data_sources.items():
            # Check if filename contains data source identifier
            for pattern in patterns.get("patterns", []):
                if pattern.lower() in filename.lower():
                    return source
        
        # Check if file type matches
        for source, patterns in file_patterns.items():
            if any(filename.endswith(ext) for ext in patterns):
                return source
        
        return "unknown"
    
    # Generate random seed
    random.seed(42)
    
    # Ensure directory exists
    Path(source_dir).mkdir(parents=True, exist_ok=True)
    
    # Collect files
    collected_files = []
    
    for root, dirs, files in os.walk(source_dir):
        for file in files:
            file_path = Path(root) / file
            relative_path = file_path.relative_to(source_dir)
            
            # Identify data source
            data_source = identify_data_source(file)
            
            # Determine target directory
            target_dir = base_dir / data_source
            target_dir.mkdir(parents=True, exist_ok=True)
            
            # Copy file
            target_path = target_dir / file
            shutil.copy2(file_path, target_path)
            
            collected_files.append({
                "source_file": str(file_path),
                "target_file": str(target_path),
                "data_source": data_source,
                "file_size": file_path.stat().st_size,
                "relative_path": str(relative_path)
            })
    
    # Save collection summary
    summary = {
        "collection_time": str(Path().cwd()),
        "source_directory": source_dir,
        "output_directory": output_dir,
        "total_files": len(collected_files),
        "files_by_source": {},
        "collected_files": collected_files
    }
    
    # Group files by data source
    for file_info in collected_files:
        source = file_info["data_source"]
        if source not in summary["files_by_source"]:
            summary["files_by_source"][source] = []
        summary["files_by_source"][source].append(file_info)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    print(f"Data collection completed. Summary saved to: {output_file}")
    print(f"Total files collected: {len(collected_files)}")
    
    for source, files in summary["files_by_source"].items():
        print(f"  {source}: {len(files)} files")
    
    return summary

def get_default_config() -> Dict[str, Any]:
    """Get default configuration"""
    return {
        "file_patterns": {
            "logs": [".log", ".evtx", ".csv"],
            "network": [".pcap", ".pcapng"],
            "system": [".txt", ".json", ".xml"]
        },
        "data_sources": {
            "victim1": {
                "patterns": ["victim1", "vm1"],
                "exact_matches": ["victim1.pcap"]
            },
            "victim2": {
                "patterns": ["victim2", "vm2"],
                "exact_matches": ["victim2.pcap"]
            }
        }
    }

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python collect_data.py <source_dir> <output_dir> [config_file]")
        sys.exit(1)
    
    source_dir = sys.argv[1]
    output_dir = sys.argv[2]
    config_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    collect_data(source_dir, output_dir, config_file)
