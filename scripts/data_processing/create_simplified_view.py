#!/usr/bin/env python3
"""
Create Simplified Dataset View
Generate a simplified view of the unified dataset for semi-automatic labeling
"""

import os
import json
import pandas as pd
import argparse
from datetime import datetime
from typing import Dict, List, Any
import re # Added for regex escaping
import sys # Added for sys.exit

def create_simplified_view(variant_id: str) -> bool:
    """Create simplified view of unified dataset for labeling"""
    try:
        print(f"Creating simplified view for variant: {variant_id}")
        
        # Load the unified dataset with absolute path
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        unified_csv = os.path.join(base_dir, f"data/processed/{variant_id}/datasets/unified_dataset.csv")
        if not os.path.exists(unified_csv):
            print(f"❌ Unified dataset not found: {unified_csv}")
            return False
        
        # Read the full dataset
        print("Loading unified dataset...")
        df = pd.read_csv(unified_csv, low_memory=False)
        print(f"📊 Loaded {len(df)} records with {len(df.columns)} columns")
        
        # Create simplified dataframe with essential fields only
        essential_fields = ['timestamp', 'variant_id', 'data_source', 'source_type', 'event_type', 'severity', 'is_attack', 'attack_stage']
        simplified_df = df[essential_fields].copy()
        
        # Merge data_source and source_type into a single field
        print("Merging data_source and source_type...")
        simplified_df['log_type'] = simplified_df['data_source'] + '_' + simplified_df['source_type']
        
        # Remove the separate fields
        simplified_df = simplified_df.drop(['data_source', 'source_type'], axis=1)
        
        # Add fields based on data source type
        print("Adding fields based on data source...")
        
        # For attack logs - add attack-specific fields
        attack_mask = df['data_source'] == 'attack_logs'
        if attack_mask.any():
            attack_fields = ['attack_type', 'attack_index', 'payload', 'status_code', 'response_length', 'response_time', 'sql_error', 'success', 'method', 'file_saved']
            for field in attack_fields:
                if field in df.columns:
                    simplified_df.loc[attack_mask, field] = df.loc[attack_mask, field]
        
        # For webapp logs - add web-specific fields
        webapp_mask = df['data_source'] == 'webapp_logs'
        if webapp_mask.any():
            web_fields = ['details_method', 'details_path', 'details_status', 'details_user_agent']
            for field in web_fields:
                if field in df.columns:
                    simplified_df.loc[webapp_mask, field] = df.loc[webapp_mask, field]
        
        # For pcap logs - add network-specific fields
        pcap_mask = df['data_source'] == 'pcap_logs'
        if pcap_mask.any():
            network_fields = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'length', 'packet_index']
            for field in network_fields:
                if field in df.columns:
                    simplified_df.loc[pcap_mask, field] = df.loc[pcap_mask, field]
        
        # For all logs - add common fields if they have data
        common_fields = ['host', 'process', 'details_raw']
        for field in common_fields:
            if field in df.columns and df[field].notna().sum() > 0:
                simplified_df[field] = df[field]
        
        # Add derived fields for labeling (without confidence)
        simplified_df['needs_review'] = False
        simplified_df['label'] = ''
        simplified_df['notes'] = ''
        
        # Auto-label based on data source and attack indicators
        print("Applying auto-labeling rules...")
        
        # Rule 1: Attack logs are definitely attacks
        attack_mask = df['data_source'] == 'attack_logs'
        simplified_df.loc[attack_mask, 'label'] = 'sql_injection_attack'
        simplified_df.loc[attack_mask, 'needs_review'] = False
        
        # Rule 2: High severity events need review
        high_severity_mask = simplified_df['severity'] == 'high'
        simplified_df.loc[high_severity_mask & (simplified_df['label'] == ''), 'needs_review'] = True
        simplified_df.loc[high_severity_mask & (simplified_df['label'] == ''), 'label'] = 'suspicious'
        
        # Rule 3: SQL error indicators (only if column exists)
        if 'sql_error' in simplified_df.columns:
            sql_error_mask = (simplified_df['sql_error'] == True) | (simplified_df['sql_error'] == 'true')
            simplified_df.loc[sql_error_mask & (simplified_df['label'] == ''), 'label'] = 'sql_error'
            simplified_df.loc[sql_error_mask & (simplified_df['label'] == ''), 'needs_review'] = True
        
        # Rule 4: Payload contains SQL keywords (only if column exists)
        if 'payload' in simplified_df.columns:
            sql_keywords = ['union', 'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter', 'exec', 'execute']
            for keyword in sql_keywords:
                sql_mask = simplified_df['payload'].str.contains(keyword, case=False, na=False)
                simplified_df.loc[sql_mask & (simplified_df['label'] == ''), 'label'] = 'sql_injection_attack'
                simplified_df.loc[sql_mask & (simplified_df['label'] == ''), 'needs_review'] = False
        
        # Rule 5: Network attacks (pcap logs with suspicious patterns)
        if 'src_ip' in simplified_df.columns and 'dst_ip' in simplified_df.columns:
            # Mark internal to external communication as suspicious
            internal_ips = ['172.16.', '192.168.', '10.', '127.0.0.1']
            external_mask = simplified_df['src_ip'].str.startswith(tuple(internal_ips), na=False) & \
                           ~simplified_df['dst_ip'].str.startswith(tuple(internal_ips), na=False)
            simplified_df.loc[external_mask & (simplified_df['label'] == ''), 'label'] = 'network_attack'
            simplified_df.loc[external_mask & (simplified_df['label'] == ''), 'needs_review'] = True
        
        # Variant-specific auto-labeling rules
        print("Applying variant-specific auto-labeling rules...")
        
        if variant_id == "lowscan_stealthy":
            # Stealthy variant: focus on subtle attack patterns
            # Rule 6a: High priority for stealth detection
            stealth_mask = simplified_df['log_type'].str.contains('dns_proxy', na=False) & \
                          (simplified_df['attack_stage'] == 'reconnaissance')
            simplified_df.loc[stealth_mask & (simplified_df['label'] == ''), 'label'] = 'stealth_reconnaissance'
            simplified_df.loc[stealth_mask & (simplified_df['label'] == ''), 'needs_review'] = True
            
            # Rule 6b: Enhanced detection for subtle patterns
            subtle_mask = simplified_df['log_type'].str.contains('http_proxy', na=False) & \
                         simplified_df['severity'].isin(['warn', 'error'])
            simplified_df.loc[subtle_mask & (simplified_df['label'] == ''), 'label'] = 'suspicious_http'
            simplified_df.loc[subtle_mask & (simplified_df['label'] == ''), 'needs_review'] = True
            
        elif variant_id == "lowscan_moderate":
            # Moderate variant: balanced detection
            # Rule 6a: Moderate priority for attack detection
            moderate_mask = simplified_df['log_type'].str.contains('dns_proxy', na=False) & \
                           (simplified_df['attack_stage'].isin(['reconnaissance', 'exfiltration']))
            simplified_df.loc[moderate_mask & (simplified_df['label'] == ''), 'label'] = 'moderate_attack'
            simplified_df.loc[moderate_mask & (simplified_df['label'] == ''), 'needs_review'] = False
            
        elif variant_id == "lowscan_aggressive":
            # Aggressive variant: focus on high-volume patterns
            # Rule 6a: High-volume attack detection
            aggressive_mask = simplified_df['log_type'].str.contains('dns_proxy', na=False) & \
                             (simplified_df['attack_stage'].isin(['reconnaissance', 'exfiltration', 'cc_communication']))
            simplified_df.loc[aggressive_mask & (simplified_df['label'] == ''), 'label'] = 'aggressive_attack'
            simplified_df.loc[aggressive_mask & (simplified_df['label'] == ''), 'needs_review'] = False
            
            # Rule 6b: High-volume HTTP patterns
            volume_mask = simplified_df['log_type'].str.contains('http_proxy', na=False) & \
                         (simplified_df['severity'] == 'error')
            simplified_df.loc[volume_mask & (simplified_df['label'] == ''), 'label'] = 'high_volume_http'
            simplified_df.loc[volume_mask & (simplified_df['label'] == ''), 'needs_review'] = False
        
        # Rule 6: Default benign for everything else
        simplified_df.loc[simplified_df['label'] == '', 'label'] = 'benign'
        
        # Create output directory with absolute path
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        output_dir = os.path.join(base_dir, f"data/processed/{variant_id}/datasets")
        os.makedirs(output_dir, exist_ok=True)
        
        # Save simplified CSV
        simplified_csv = f"{output_dir}/simplified_view.csv"
        simplified_df.to_csv(simplified_csv, index=False)
        
        # Save Excel file with multiple sheets
        simplified_excel = f"{output_dir}/simplified_view.xlsx"
        with pd.ExcelWriter(simplified_excel, engine='openpyxl') as writer:
            simplified_df.to_excel(writer, sheet_name='Labeling_View', index=False)
            
            # Create summary sheet
            summary_data = {
                'Metric': [
                    'Total Records',
                    'Records Needing Review',
                    'Auto-labeled Records',
                    'Attack Records',
                    'Benign Records',
                    'Suspicious Records',
                    'SQL Injection Attacks',
                    'Network Attacks',
                    'Application Errors'
                ],
                'Count': [
                    len(simplified_df),
                    len(simplified_df[simplified_df['needs_review'] == True]),
                    len(simplified_df[simplified_df['label'] != '']),
                    len(simplified_df[simplified_df['label'].str.contains('attack', case=False, na=False)]),
                    len(simplified_df[simplified_df['label'] == 'benign']),
                    len(simplified_df[simplified_df['label'] == 'suspicious']),
                    len(simplified_df[simplified_df['label'].str.contains('sql_injection', case=False, na=False)]),
                    len(simplified_df[simplified_df['label'] == 'network_attack']),
                    len(simplified_df[simplified_df['label'] == 'application_error'])
                ]
            }
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            # Create log type breakdown sheet
            log_type_breakdown = simplified_df['log_type'].value_counts().reset_index()
            log_type_breakdown.columns = ['Log Type', 'Record Count']
            log_type_breakdown.to_excel(writer, sheet_name='Log_Type_Breakdown', index=False)
            
            # Create label breakdown sheet
            label_breakdown = simplified_df['label'].value_counts().reset_index()
            label_breakdown.columns = ['Label', 'Record Count']
            label_breakdown.to_excel(writer, sheet_name='Label_Breakdown', index=False)
        
        # Create summary report
        summary_file = f"{output_dir}/simplified_view_summary.txt"
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(f"Simplified Dataset View Summary for {variant_id}\n")
            f.write("=" * 60 + "\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"Total records: {len(simplified_df)}\n")
            f.write(f"Key fields: {len([f for f in essential_fields if f in simplified_df.columns])}\n\n")
            
            f.write("Auto-labeling Results:\n")
            f.write("-" * 30 + "\n")
            f.write(f"Records needing review: {len(simplified_df[simplified_df['needs_review'] == True])}\n")
            f.write(f"Auto-labeled records: {len(simplified_df[simplified_df['label'] != ''])}\n\n")
            
            f.write("Label Distribution:\n")
            f.write("-" * 30 + "\n")
            label_counts = simplified_df['label'].value_counts()
            for label, count in label_counts.items():
                percentage = (count / len(simplified_df)) * 100
                f.write(f"{label}: {count} ({percentage:.1f}%)\n")
            
            f.write(f"\nOutput files:\n")
            f.write(f"- CSV view: {simplified_csv}\n")
            f.write(f"- Excel view: {simplified_excel}\n")
            f.write(f"- Summary: {summary_file}\n")
            
            f.write(f"\nLabeling Instructions:\n")
            f.write("-" * 30 + "\n")
            f.write("1. Open the Excel file for easy editing\n")
            f.write("2. Review records marked with 'needs_review' = True\n")
            f.write("3. Update 'label' field with correct classification\n")
            f.write("4. Add notes in 'notes' field if needed\n")
            f.write("5. Save and use for training ML models\n")
        
        print(f"\n✅ Simplified view created successfully!")
        print(f"📊 Total records: {len(simplified_df)}")
        print(f"🔍 Records needing review: {len(simplified_df[simplified_df['needs_review'] == True])}")
        print(f"🏷️  Auto-labeled records: {len(simplified_df[simplified_df['label'] != ''])}")
        print(f"📁 Output directory: {output_dir}")
        print(f"📄 CSV file: {simplified_csv}")
        print(f"📊 Excel file: {simplified_excel}")
        print(f"📝 Summary file: {summary_file}")
        
        # Print label distribution
        print(f"\n🏷️  Label distribution:")
        label_counts = simplified_df['label'].value_counts()
        for label, count in label_counts.items():
            percentage = (count / len(simplified_df)) * 100
            print(f"  {label}: {count} ({percentage:.1f}%)")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating simplified view: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Create simplified dataset view for labeling")
    parser.add_argument("--variant-id", required=True, help="Variant ID to process")
    
    args = parser.parse_args()
    create_simplified_view(args.variant_id)

if __name__ == "__main__":
    main() 