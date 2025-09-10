#!/usr/bin/env python3
"""
Advanced Attack Analysis Hook
Analyzes multi-phase attack results and generates comprehensive reports
Works with 3-phase and 4-phase attack scenarios
"""

import os
import json
import sys
import logging
import shutil
from datetime import datetime
from pathlib import Path

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def analyze_attack_logs(logs_dir):
    """Analyze attack logs for three-phase attack evidence"""
    results = {
        "analysis_timestamp": datetime.now().isoformat(),
        "phases_detected": {},
        "attack_summary": {},
        "exfiltrated_data": []
    }
    
    # Look for attack log files (3-phase and 4-phase scenarios)
    attack_logs = []
    attack_patterns = [
        "attack_shell_acquisition.log", 
        "attack_c2_communication.log", 
        "attack_data_exfiltration.log",
        "attack_lateral_movement.log"  # 4-phase support
    ]
    for pattern in attack_patterns:
        log_path = os.path.join(logs_dir, "attacker", pattern)
        if os.path.exists(log_path):
            attack_logs.append((pattern, log_path))
    
    # Analyze each phase
    for log_name, log_path in attack_logs:
        phase = log_name.split('_')[1]  # Extract phase name
        phase_results = analyze_phase_log(log_path, phase)
        results["phases_detected"][phase] = phase_results
        
    # Look for attack report
    report_path = os.path.join(logs_dir, "attacker", "advanced_attack_report.json")
    if os.path.exists(report_path):
        try:
            with open(report_path, 'r') as f:
                attack_report = json.load(f)
                results["attack_summary"] = attack_report
        except Exception as e:
            logger.warning(f"Failed to parse attack report: {e}")
    
    # Check for exfiltrated data
    shared_data_dir = os.path.join(os.path.dirname(logs_dir), "shared_data")
    if os.path.exists(shared_data_dir):
        exfil_files = []
        for file in os.listdir(shared_data_dir):
            if file.endswith('.tar.gz') and 'exfiltrat' in file:
                file_path = os.path.join(shared_data_dir, file)
                file_info = {
                    "filename": file,
                    "size": os.path.getsize(file_path),
                    "timestamp": datetime.fromtimestamp(os.path.getctime(file_path)).isoformat()
                }
                exfil_files.append(file_info)
        results["exfiltrated_data"] = exfil_files
    
    return results

def analyze_phase_log(log_path, phase):
    """Analyze individual phase log file"""
    phase_results = {
        "phase_name": phase,
        "log_file": log_path,
        "events_found": [],
        "success_indicators": [],
        "timestamps": []
    }
    
    try:
        with open(log_path, 'r') as f:
            content = f.read()
            
        # Look for JSON events
        lines = content.split('\n')
        for line in lines:
            if line.strip().startswith('{') and '"timestamp"' in line:
                try:
                    event = json.loads(line.strip())
                    phase_results["events_found"].append(event)
                    if event.get("timestamp"):
                        phase_results["timestamps"].append(event["timestamp"])
                except:
                    pass
            
            # Look for success indicators
            if "✓" in line or "SUCCESS" in line or "completed" in line:
                phase_results["success_indicators"].append(line.strip())
                
    except Exception as e:
        logger.warning(f"Failed to analyze {log_path}: {e}")
        
    return phase_results

def extract_exfiltrated_data(logs_dir):
    """Extract and analyze exfiltrated data files"""
    extraction_dir = os.path.join(os.path.dirname(logs_dir), "analysis", "exfiltrated_data")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = os.path.join(extraction_dir, f"report_{timestamp}")
    
    # Create analysis directory
    os.makedirs(report_dir, exist_ok=True)
    
    # Look for shared data
    shared_data_dir = os.path.join(os.path.dirname(logs_dir), "shared_data")
    extracted_files = []
    
    if os.path.exists(shared_data_dir):
        for file in os.listdir(shared_data_dir):
            if file.endswith('.tar.gz'):
                src_path = os.path.join(shared_data_dir, file)
                dst_path = os.path.join(report_dir, file)
                shutil.copy2(src_path, dst_path)
                extracted_files.append(file)
                
                # Try to extract the tar file
                extract_dir = os.path.join(report_dir, file.replace('.tar.gz', '_extracted'))
                try:
                    import tarfile
                    with tarfile.open(src_path, 'r:gz') as tar:
                        tar.extractall(extract_dir)
                    logger.info(f"Extracted {file} to {extract_dir}")
                except Exception as e:
                    logger.warning(f"Failed to extract {file}: {e}")
    
    return report_dir, extracted_files

def generate_report(analysis_results, logs_dir):
    """Generate comprehensive analysis report"""
    report_dir, extracted_files = extract_exfiltrated_data(logs_dir)
    
    # Add extraction info to results
    analysis_results["data_extraction"] = {
        "extraction_directory": report_dir,
        "extracted_files": extracted_files
    }
    
    # Save JSON report
    json_report_path = os.path.join(report_dir, "advanced_attack_analysis.json")
    with open(json_report_path, 'w') as f:
        json.dump(analysis_results, f, indent=2)
    
    # Generate markdown report
    md_report_path = os.path.join(report_dir, "advanced_attack_analysis.md")
    with open(md_report_path, 'w') as f:
        f.write("# Advanced Three-Phase Attack Analysis Report\n\n")
        f.write(f"**Analysis Date:** {analysis_results['analysis_timestamp']}\n\n")
        
        # Phase analysis
        f.write("## Attack Phases Analysis\n\n")
        for phase, results in analysis_results.get("phases_detected", {}).items():
            f.write(f"### Phase: {phase.title()}\n")
            f.write(f"- **Events Found:** {len(results.get('events_found', []))}\n")
            f.write(f"- **Success Indicators:** {len(results.get('success_indicators', []))}\n")
            if results.get("timestamps"):
                f.write(f"- **First Event:** {results['timestamps'][0]}\n")
                f.write(f"- **Last Event:** {results['timestamps'][-1]}\n")
            f.write("\n")
        
        # Exfiltrated data
        f.write("## Exfiltrated Data Analysis\n\n")
        exfil_data = analysis_results.get("exfiltrated_data", [])
        if exfil_data:
            for file_info in exfil_data:
                f.write(f"- **File:** {file_info['filename']}\n")
                f.write(f"  - Size: {file_info['size']} bytes\n")
                f.write(f"  - Created: {file_info['timestamp']}\n")
        else:
            f.write("No exfiltrated data files found.\n")
        
        f.write("\n## Data Extraction\n\n")
        f.write(f"- **Extraction Directory:** {report_dir}\n")
        f.write(f"- **Extracted Files:** {len(extracted_files)}\n")
        
        for file in extracted_files:
            f.write(f"  - {file}\n")
    
    logger.info(f"Analysis report generated: {md_report_path}")
    return md_report_path

def main():
    """Main analysis function"""
    if len(sys.argv) < 2:
        logger.error("Usage: analyze_advanced_attack.py <logs_directory>")
        sys.exit(1)
    
    logs_dir = sys.argv[1]
    
    if not os.path.exists(logs_dir):
        logger.error(f"Logs directory not found: {logs_dir}")
        sys.exit(1)
    
    logger.info(f"Starting advanced attack analysis for: {logs_dir}")
    
    # Perform analysis
    analysis_results = analyze_attack_logs(logs_dir)
    
    # Generate report
    report_path = generate_report(analysis_results, logs_dir)
    
    logger.info("Advanced attack analysis completed successfully")
    logger.info(f"Report available at: {report_path}")

if __name__ == "__main__":
    main()
