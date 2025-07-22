#!/usr/bin/env python3
"""
Show Extracted Data - Display actual sensitive data from successful attacks
"""

import json
import sys
import os
from datetime import datetime

def show_extracted_data(variant_id, save_to_file=True):
    """Show actual extracted data from the attack"""
    output_lines = []
    
    output_lines.append(f"🔍 Extracted Data Analysis for {variant_id}")
    output_lines.append("=" * 60)
    
    # Check attack results
    attack_results_file = f"data/processed/{variant_id}/attack_logs/attack_results.jsonl"
    if not os.path.exists(attack_results_file):
        output_lines.append(f"❌ Attack results file not found: {attack_results_file}")
        if save_to_file:
            return output_lines
        else:
            print("\n".join(output_lines))
            return
    
    # Read attack results
    with open(attack_results_file, 'r') as f:
        attack_data = json.loads(f.read())
    
    output_lines.append("📊 Attack Summary:")
    output_lines.append(f"   Variant ID: {attack_data.get('variant_id', 'N/A')}")
    
    # Analyze login injections
    login_injections = attack_data.get('custom_tests', {}).get('login_injections', [])
    successful_logins = [inj for inj in login_injections if inj.get('success', False)]
    failed_logins = [inj for inj in login_injections if not inj.get('success', False)]
    
    output_lines.append(f"   Login Injections: {len(successful_logins)} successful, {len(failed_logins)} failed")
    
    # Analyze search injections
    search_injections = attack_data.get('custom_tests', {}).get('search_injections', [])
    output_lines.append(f"   Search Injections: {len(search_injections)} attempted")
    
    # Show successful login payloads
    if successful_logins:
        output_lines.append("\n✅ Successful Login Payloads:")
        for i, inj in enumerate(successful_logins, 1):
            output_lines.append(f"   {i}. {inj['payload']}")
            output_lines.append(f"      Status: {inj['status_code']}, Time: {inj['response_time']:.3f}s")
    
    # Show failed login payloads
    if failed_logins:
        output_lines.append("\n❌ Failed Login Payloads:")
        for i, inj in enumerate(failed_logins, 1):
            output_lines.append(f"   {i}. {inj['payload']}")
            output_lines.append(f"      Status: {inj['status_code']}, Error: {inj.get('sql_error', 'Unknown')}")
    
    # Analyze data extraction
    data_extraction = attack_data.get('data_extraction', {})
    if data_extraction:
        output_lines.append(f"\n🔐 Data Extraction Results:")
        output_lines.append(f"   Method: {data_extraction.get('method', 'N/A')}")
        output_lines.append(f"   Payload: {data_extraction.get('payload', 'N/A')}")
        output_lines.append(f"   Success: {data_extraction.get('success', False)}")
        output_lines.append(f"   Status Code: {data_extraction.get('status_code', 'N/A')}")
        
        if data_extraction.get('success', False):
            output_lines.append("   ✅ Data extraction was successful!")
        else:
            output_lines.append("   ❌ Data extraction failed")
    
    # Try to get actual database data
    output_lines.append(f"\n🗄️  Database Content Analysis:")
    
    # Check if we can access the database directly
    try:
        import sqlite3
        db_path = f"data/logs/{variant_id}/database.sqlite"
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Get users table
            cursor.execute("SELECT * FROM users")
            users = cursor.fetchall()
            
            output_lines.append(f"   Users table: {len(users)} records found")
            for i, user in enumerate(users, 1):
                output_lines.append(f"   User {i}: ID={user[0]}, Username={user[1]}, Email={user[3]}, Role={user[4]}")
            
            # Get products table
            cursor.execute("SELECT * FROM products")
            products = cursor.fetchall()
            
            output_lines.append(f"   Products table: {len(products)} records found")
            for i, product in enumerate(products, 1):
                output_lines.append(f"   Product {i}: ID={product[0]}, Name={product[1]}, Price=${product[2]}")
            
            conn.close()
        else:
            output_lines.append("   Database file not found in logs directory")
            
    except Exception as e:
        output_lines.append(f"   Error accessing database: {e}")
    
    # Show actual extracted data file content
    extracted_file = f"data/logs/{variant_id}/output/extracted_data.html"
    if os.path.exists(extracted_file):
        output_lines.append(f"\n📄 Extracted Data File Content:")
        output_lines.append(f"   File: {extracted_file}")
        
        with open(extracted_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Extract the actual data from HTML
        if '<!--' in content:
            # Split by comments to get the actual data
            parts = content.split('<!--')
            if len(parts) > 1:
                actual_data = parts[-1].split('-->')[-1].strip()
                if actual_data:
                    output_lines.append("   Actual Extracted Data:")
                    output_lines.append("   " + "-" * 40)
                    output_lines.append(f"   {actual_data[:500]}...")  # Show first 500 chars
                else:
                    output_lines.append("   No actual data found in file")
            else:
                output_lines.append("   File contains only metadata")
        else:
            output_lines.append("   File format not recognized")
    else:
        output_lines.append(f"\n❌ Extracted data file not found: {extracted_file}")
    
    # Show webapp logs for login attempts
    login_log_file = f"data/logs/{variant_id}/logs/login_attempts.log"
    if os.path.exists(login_log_file):
        output_lines.append(f"\n📝 Login Attempts Log:")
        with open(login_log_file, 'r') as f:
            lines = f.readlines()
            output_lines.append(f"   Total login attempts: {len(lines)}")
            if lines:
                output_lines.append("   Recent attempts:")
                for line in lines[-5:]:  # Show last 5 attempts
                    output_lines.append(f"   {line.strip()}")
    
    output_lines.append("\n" + "=" * 60)
    
    # Save to file if requested
    if save_to_file:
        # Create analysis directory
        analysis_dir = f"data/processed/{variant_id}/analysis"
        os.makedirs(analysis_dir, exist_ok=True)
        
        # Save detailed analysis
        analysis_file = f"{analysis_dir}/extracted_data_analysis.txt"
        with open(analysis_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(output_lines))
        
        # Also save as JSON for programmatic access
        analysis_json = {
            "variant_id": variant_id,
            "timestamp": datetime.now().isoformat(),
            "attack_summary": {
                "login_injections": {
                    "total": len(login_injections),
                    "successful": len(successful_logins),
                    "failed": len(failed_logins),
                    "success_rate": (len(successful_logins)/len(login_injections)*100) if login_injections else 0
                },
                "search_injections": {
                    "total": len(search_injections),
                    "successful": len([inj for inj in search_injections if not inj.get('sql_error', False)]),
                    "failed": len([inj for inj in search_injections if inj.get('sql_error', False)]),
                    "success_rate": (len([inj for inj in search_injections if not inj.get('sql_error', False)])/len(search_injections)*100) if search_injections else 0
                },
                "data_extraction": data_extraction
            },
            "successful_payloads": {
                "login": [{"payload": inj['payload'], "status_code": inj['status_code'], "response_time": inj['response_time']} for inj in successful_logins],
                "search": [{"payload": inj['payload'], "status_code": inj['status_code'], "response_time": inj['response_time']} for inj in search_injections if not inj.get('sql_error', False)]
            },
            "failed_payloads": {
                "login": [{"payload": inj['payload'], "status_code": inj['status_code'], "error": inj.get('sql_error', 'Unknown')} for inj in failed_logins],
                "search": [{"payload": inj['payload'], "status_code": inj['status_code'], "error": inj.get('sql_error', 'Unknown')} for inj in search_injections if inj.get('sql_error', False)]
            }
        }
        
        json_file = f"{analysis_dir}/extracted_data_analysis.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(analysis_json, f, indent=2, ensure_ascii=False)
        
        output_lines.append(f"\n💾 Analysis saved to:")
        output_lines.append(f"   Text: {analysis_file}")
        output_lines.append(f"   JSON: {json_file}")
    
    # Print to console
    print("\n".join(output_lines))
    
    return output_lines

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/show_extracted_data.py <variant_id>")
        print("Example: python3 scripts/show_extracted_data.py lowscan_aggressive")
        sys.exit(1)
    
    variant_id = sys.argv[1]
    show_extracted_data(variant_id, save_to_file=True)

if __name__ == "__main__":
    main() 