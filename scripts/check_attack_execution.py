#!/usr/bin/env python3
"""
Attack Execution Check Script
验证攻击的每一步是否正确执行
"""

import os
import json
import argparse
from datetime import datetime
from typing import Dict, List, Any

def check_attack_phases(variant_id: str) -> Dict[str, Any]:
    """检查攻击的各个阶段"""
    results = {
        "variant_id": variant_id,
        "timestamp": datetime.now().isoformat(),
        "phases": {},
        "summary": {}
    }
    
    # 检查攻击日志文件
    attack_log_path = f"data/logs/{variant_id}/output/attack.log"
    if os.path.exists(attack_log_path):
        results["phases"]["attack_log"] = check_attack_log(attack_log_path)
    
    # 检查攻击结果
    attack_results_path = f"data/processed/{variant_id}/attack_logs/attack_results.jsonl"
    if os.path.exists(attack_results_path):
        results["phases"]["attack_results"] = check_attack_results(attack_results_path)
    
    # 检查网络扫描
    scan_results_path = f"data/logs/{variant_id}/output/scan_results.json"
    if os.path.exists(scan_results_path):
        results["phases"]["network_scan"] = check_network_scan(scan_results_path)
    
    # 检查Web应用日志
    nginx_access_path = f"data/logs/{variant_id}/nginx/access.log"
    if os.path.exists(nginx_access_path):
        results["phases"]["web_logs"] = check_web_logs(nginx_access_path)
    
    # 检查数据提取
    extracted_data_path = f"data/logs/{variant_id}/output/extracted_data.html"
    if os.path.exists(extracted_data_path):
        results["phases"]["data_extraction"] = check_data_extraction(extracted_data_path)
    
    # 检查PCAP文件
    pcap_dir = f"data/logs/{variant_id}/pcap/"
    if os.path.exists(pcap_dir):
        results["phases"]["network_capture"] = check_network_capture(pcap_dir)
    
    # 生成总结
    results["summary"] = generate_summary(results["phases"])
    
    return results

def check_attack_log(log_path: str) -> Dict[str, Any]:
    """检查攻击日志"""
    result = {
        "status": "success",
        "phases": [],
        "errors": []
    }
    
    try:
        with open(log_path, 'r') as f:
            lines = f.readlines()
        
        # 检查关键阶段
        phases = {
            "connectivity": "Container Connectivity",
            "reconnaissance": "Network Reconnaissance",
            "enumeration": "Web Application Enumeration", 
            "sql_injection": "Custom SQL Injection",
        
            "data_extraction": "Data Extraction"
        }
        
        for phase_name, phase_keyword in phases.items():
            phase_lines = [line for line in lines if phase_keyword in line]
            if phase_lines:
                result["phases"].append({
                    "name": phase_name,
                    "status": "executed",
                    "timestamp": extract_timestamp(phase_lines[0]),
                    "details": len(phase_lines)
                })
            else:
                result["phases"].append({
                    "name": phase_name,
                    "status": "not_found",
                    "timestamp": None,
                    "details": 0
                })
        
        # 检查错误
        error_lines = [line for line in lines if "ERROR" in line or "FAILED" in line]
        result["errors"] = len(error_lines)
        
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

def check_attack_results(results_path: str) -> Dict[str, Any]:
    """检查攻击结果"""
    result = {
        "status": "success",
        "tests": {},
        "success_rate": 0
    }
    
    try:
        with open(results_path, 'r') as f:
            data = json.loads(f.readline())
        
        # 检查自定义测试
        if "custom_tests" in data:
            custom_tests = data["custom_tests"]
            total_tests = 0
            successful_tests = 0
            
            for test_type, tests in custom_tests.items():
                if isinstance(tests, list):
                    total_tests += len(tests)
                    successful_tests += sum(1 for test in tests if test.get("success", False))
                    result["tests"][test_type] = {
                        "total": len(tests),
                        "successful": sum(1 for test in tests if test.get("success", False)),
                        "success_rate": sum(1 for test in tests if test.get("success", False)) / len(tests) * 100
                    }
            
            if total_tests > 0:
                result["success_rate"] = successful_tests / total_tests * 100
        
        # 检查数据提取
        if "data_extraction" in data:
            result["data_extraction"] = {
                "status": "success" if data["data_extraction"].get("file_saved", False) else "failed",
                "payload": data["data_extraction"].get("payload", ""),
                "status_code": data["data_extraction"].get("status_code", 0)
            }
        
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

def check_network_scan(scan_path: str) -> Dict[str, Any]:
    """检查网络扫描结果"""
    result = {
        "status": "success",
        "tools": {}
    }
    
    try:
        with open(scan_path, 'r') as f:
            data = json.load(f)
        
        for tool, info in data.items():
            result["tools"][tool] = {
                "status": "success" if info.get("returncode", 1) == 0 else "failed",
                "returncode": info.get("returncode", 1),
                "timestamp": info.get("timestamp", ""),
                "has_output": bool(info.get("stdout", ""))
            }
        
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

def check_web_logs(access_log_path: str) -> Dict[str, Any]:
    """检查Web应用日志"""
    result = {
        "status": "success",
        "attack_requests": 0,
        "sql_injection_requests": 0,
        "admin_requests": 0
    }
    
    try:
        with open(access_log_path, 'r') as f:
            lines = f.readlines()
        
        # 统计攻击相关请求
        for line in lines:
            if "admin" in line.lower():
                result["admin_requests"] += 1
            if "sql" in line.lower() or "injection" in line.lower():
                result["sql_injection_requests"] += 1
            if "login.php" in line or "search.php" in line:
                result["attack_requests"] += 1
        
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

def check_data_extraction(extracted_data_path: str) -> Dict[str, Any]:
    """检查数据提取结果"""
    result = {
        "status": "success",
        "file_exists": True,
        "file_size": 0,
        "has_data": False
    }
    
    try:
        result["file_size"] = os.path.getsize(extracted_data_path)
        
        with open(extracted_data_path, 'r') as f:
            content = f.read()
            result["has_data"] = len(content) > 100  # 简单检查是否有实际数据
        
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        result["file_exists"] = False
    
    return result

def check_network_capture(pcap_dir: str) -> Dict[str, Any]:
    """检查网络捕获"""
    result = {
        "status": "success",
        "files": [],
        "total_size": 0
    }
    
    try:
        for file in os.listdir(pcap_dir):
            if file.endswith('.pcap'):
                file_path = os.path.join(pcap_dir, file)
                file_size = os.path.getsize(file_path)
                result["files"].append({
                    "name": file,
                    "size": file_size,
                    "size_mb": file_size / (1024 * 1024)
                })
                result["total_size"] += file_size
        
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    
    return result

def extract_timestamp(line: str) -> str:
    """从日志行中提取时间戳"""
    try:
        # 格式: 2025-07-21 11:10:42,831 - INFO - ...
        timestamp_str = line.split(" - ")[0]
        return timestamp_str
    except:
        return ""

def generate_summary(phases: Dict[str, Any]) -> Dict[str, Any]:
    """生成总结"""
    summary = {
        "total_phases": len(phases),
        "successful_phases": 0,
        "failed_phases": 0,
        "overall_status": "unknown"
    }
    
    for phase_name, phase_result in phases.items():
        if phase_result.get("status") == "success":
            summary["successful_phases"] += 1
        else:
            summary["failed_phases"] += 1
    
    if summary["successful_phases"] == summary["total_phases"]:
        summary["overall_status"] = "success"
    elif summary["failed_phases"] == summary["total_phases"]:
        summary["overall_status"] = "failed"
    else:
        summary["overall_status"] = "partial"
    
    return summary

def print_results(results: Dict[str, Any]):
    """打印检查结果"""
    print("=" * 60)
    print(f"🔍 Attack Execution Check Results")
    print(f"📋 Variant ID: {results['variant_id']}")
    print(f"⏰ Timestamp: {results['timestamp']}")
    print("=" * 60)
    
    # 打印各阶段结果
    for phase_name, phase_result in results["phases"].items():
        status_icon = "✅" if phase_result.get("status") == "success" else "❌"
        print(f"\n{status_icon} {phase_name.upper().replace('_', ' ')}")
        print(f"   Status: {phase_result.get('status', 'unknown')}")
        
        if "phases" in phase_result:
            for sub_phase in phase_result["phases"]:
                sub_status = "✅" if sub_phase["status"] == "executed" else "❌"
                print(f"   {sub_status} {sub_phase['name']}: {sub_phase['status']}")
        
        if "success_rate" in phase_result:
            print(f"   Success Rate: {phase_result['success_rate']:.1f}%")
        
        if "tools" in phase_result:
            for tool, tool_info in phase_result["tools"].items():
                tool_status = "✅" if tool_info["status"] == "success" else "❌"
                print(f"   {tool_status} {tool}: {tool_info['status']}")
    
    # 打印总结
    summary = results["summary"]
    print(f"\n📊 SUMMARY")
    print(f"   Total Phases: {summary['total_phases']}")
    print(f"   Successful: {summary['successful_phases']}")
    print(f"   Failed: {summary['failed_phases']}")
    print(f"   Overall Status: {summary['overall_status'].upper()}")
    
    if summary["overall_status"] == "success":
        print("\n🎉 All attack phases executed successfully!")
    elif summary["overall_status"] == "partial":
        print("\n⚠️  Some attack phases failed or were incomplete.")
    else:
        print("\n❌ Attack execution failed.")

def main():
    parser = argparse.ArgumentParser(description="Check attack execution")
    parser.add_argument("--variant-id", required=True, help="Variant ID to check")
    parser.add_argument("--output", help="Output file for results")
    
    args = parser.parse_args()
    
    # 执行检查
    results = check_attack_phases(args.variant_id)
    
    # 打印结果
    print_results(results)
    
    # 保存结果
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 Results saved to: {args.output}")

if __name__ == "__main__":
    main() 