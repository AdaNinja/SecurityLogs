#!/usr/bin/env python3
"""
Simple Suricata Validation Script

A simplified version to test the validation framework with existing data.
"""

import json
import pandas as pd
import numpy as np
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def analyze_experiment_data():
    """Analyze existing experiment data"""
    base_path = Path("/mnt/mypassport/cyberrange_data/runs")
    
    # Group A (No Suricata)
    group_a_path = base_path / "A_no_suri"
    group_b_path = base_path / "suricata_validation" / "with_suri"
    
    logger.info("=== Suricata Validation Analysis ===")
    
    # Analyze Group A
    logger.info("Analyzing Group A (No Suricata)...")
    group_a_runs = []
    for run_dir in sorted(group_a_path.glob("run_*")):
        if run_dir.is_dir():
            logger.info(f"Processing {run_dir.name}")
            
            # Check for output files
            output_dir = run_dir / "output"
            if output_dir.exists():
                files = list(output_dir.glob("*.csv"))
                logger.info(f"  Found {len(files)} CSV files")
                
                # Load attack data if available
                attack_csv = output_dir / "attacker_attacks.csv"
                if attack_csv.exists():
                    df = pd.read_csv(attack_csv)
                    logger.info(f"  Attack records: {len(df)}")
                    group_a_runs.append({
                        'run': run_dir.name,
                        'attack_count': len(df),
                        'attack_types': df['attack_type'].value_counts().to_dict() if 'attack_type' in df.columns else {}
                    })
    
    # Analyze Group B
    logger.info("Analyzing Group B (With Suricata)...")
    group_b_runs = []
    for run_dir in sorted(group_b_path.glob("run_*")):
        if run_dir.is_dir():
            logger.info(f"Processing {run_dir.name}")
            
            # Check for suricata log
            suricata_log = run_dir / "suricata.log"
            if suricata_log.exists():
                logger.info(f"  Suricata log found: {suricata_log.stat().st_size} bytes")
                
                # Count alerts
                alert_count = 0
                try:
                    with open(suricata_log, 'r') as f:
                        for line in f:
                            if line.strip():
                                try:
                                    alert = json.loads(line)
                                    if 'alert' in alert:
                                        alert_count += 1
                                except json.JSONDecodeError:
                                    continue
                    
                    logger.info(f"  Suricata alerts: {alert_count}")
                    group_b_runs.append({
                        'run': run_dir.name,
                        'suricata_alerts': alert_count
                    })
                except Exception as e:
                    logger.error(f"  Error reading Suricata log: {e}")
    
    # Summary
    logger.info("\n=== Validation Summary ===")
    logger.info(f"Group A runs analyzed: {len(group_a_runs)}")
    logger.info(f"Group B runs analyzed: {len(group_b_runs)}")
    
    if group_a_runs:
        attack_counts = [run['attack_count'] for run in group_a_runs]
        logger.info(f"Group A attack counts: {attack_counts}")
        logger.info(f"Group A mean attacks: {np.mean(attack_counts):.1f}")
        logger.info(f"Group A std dev: {np.std(attack_counts):.1f}")
        if np.mean(attack_counts) > 0:
            cv = np.std(attack_counts) / np.mean(attack_counts)
            logger.info(f"Group A coefficient of variation: {cv:.3f} ({cv*100:.1f}%)")
    
    if group_b_runs:
        alert_counts = [run['suricata_alerts'] for run in group_b_runs]
        logger.info(f"Group B Suricata alerts: {alert_counts}")
        logger.info(f"Group B mean alerts: {np.mean(alert_counts):.1f}")
    
    # Validation status
    logger.info("\n=== Validation Status ===")
    if len(group_a_runs) >= 3:
        logger.info("✅ Group A: Sufficient runs for analysis")
    else:
        logger.info("❌ Group A: Insufficient runs (need 3)")
    
    if len(group_b_runs) >= 1:
        logger.info("✅ Group B: Has Suricata data")
    else:
        logger.info("❌ Group B: No Suricata data found")
    
    return {
        'group_a': group_a_runs,
        'group_b': group_b_runs,
        'validation_ready': len(group_a_runs) >= 3 and len(group_b_runs) >= 1
    }

if __name__ == "__main__":
    try:
        results = analyze_experiment_data()
        
        # Save results
        output_file = Path("/mnt/mypassport/cyberrange_data/runs/evaluation/suricata_validation/comparison_results/simple_analysis.json")
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"\nResults saved to: {output_file}")
        
        if results['validation_ready']:
            logger.info("🎉 Validation framework is ready for full analysis!")
            exit(0)
        else:
            logger.info("⚠️  Need more data for complete validation")
            exit(1)
            
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        exit(1)
