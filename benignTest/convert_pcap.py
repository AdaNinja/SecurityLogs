#!/usr/bin/env python3
"""
PCAP File Conversion Script
Convert pcap files to readable text format for analysis
"""

import os
import subprocess
import json
from pathlib import Path
from datetime import datetime

def convert_pcap_to_text(pcap_file, output_file):
    """Convert pcap file to readable text format using tcpdump"""
    try:
        # Use tcpdump to convert pcap to readable format
        result = subprocess.run([
            'tcpdump', '-r', pcap_file, '-n', '-tttt', '-v'
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"# PCAP Analysis: {pcap_file}\n")
                f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total packets: {len(result.stdout.splitlines())}\n")
                f.write("=" * 80 + "\n\n")
                f.write(result.stdout)
            return True
        else:
            print(f"Error converting {pcap_file}: {result.stderr}")
            return False
    except Exception as e:
        print(f"Exception converting {pcap_file}: {e}")
        return False

def extract_http_flows(pcap_file, output_file):
    """Extract HTTP flows from pcap file"""
    try:
        # Use tshark to extract HTTP flows
        result = subprocess.run([
            'tshark', '-r', pcap_file, '-Y', 'http', '-T', 'json'
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0 and result.stdout.strip():
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"# HTTP Flows Analysis: {pcap_file}\n")
                f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                
                # Parse JSON and format nicely
                try:
                    flows = json.loads(result.stdout)
                    for i, flow in enumerate(flows, 1):
                        f.write(f"Flow {i}:\n")
                        f.write(f"  Source: {flow.get('_source', {}).get('layers', {}).get('ip', {}).get('ip.src', 'N/A')}\n")
                        f.write(f"  Destination: {flow.get('_source', {}).get('layers', {}).get('ip', {}).get('ip.dst', 'N/A')}\n")
                        f.write(f"  Method: {flow.get('_source', {}).get('layers', {}).get('http', {}).get('http.request.method', 'N/A')}\n")
                        f.write(f"  Host: {flow.get('_source', {}).get('layers', {}).get('http', {}).get('http.host', 'N/A')}\n")
                        f.write(f"  URI: {flow.get('_source', {}).get('layers', {}).get('http', {}).get('http.request.uri', 'N/A')}\n")
                        f.write(f"  User-Agent: {flow.get('_source', {}).get('layers', {}).get('http', {}).get('http.user_agent', 'N/A')}\n")
                        f.write("-" * 40 + "\n")
                except json.JSONDecodeError:
                    f.write("Raw output:\n")
                    f.write(result.stdout)
            return True
        else:
            # If no HTTP flows, create empty file with header
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"# HTTP Flows Analysis: {pcap_file}\n")
                f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                f.write("No HTTP flows found in this pcap file.\n")
            return True
    except Exception as e:
        print(f"Exception extracting HTTP flows from {pcap_file}: {e}")
        return False

def generate_pcap_summary(pcap_file, output_file):
    """Generate summary statistics for pcap file"""
    try:
        # Get basic statistics
        result = subprocess.run([
            'capinfos', pcap_file
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"# PCAP Summary: {pcap_file}\n")
                f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                f.write(result.stdout)
            return True
        else:
            print(f"Error generating summary for {pcap_file}: {result.stderr}")
            return False
    except Exception as e:
        print(f"Exception generating summary for {pcap_file}: {e}")
        return False

def convert_all_pcaps():
    """Convert all pcap files in the current directory structure"""
    print("=== PCAP File Conversion ===")
    
    base_path = Path(".")
    rounds = ['round1', 'round2', 'round3']
    victims = ['victim1', 'victim2']
    
    total_converted = 0
    total_files = 0
    
    for round_num in rounds:
        print(f"\n📊 Processing {round_num}...")
        
        for victim in victims:
            victim_path = base_path / round_num / victim
            if not victim_path.exists():
                continue
            
            print(f"  🔍 Processing {victim}...")
            
            # Find all pcap files
            pcap_files = list(victim_path.glob("*.pcap"))
            total_files += len(pcap_files)
            
            for pcap_file in pcap_files:
                print(f"    Converting {pcap_file.name}...")
                
                # Create analysis directory
                analysis_dir = victim_path / "pcap_analysis"
                analysis_dir.mkdir(exist_ok=True)
                
                # Convert to readable text
                text_file = analysis_dir / f"{pcap_file.stem}_readable.txt"
                if convert_pcap_to_text(str(pcap_file), str(text_file)):
                    total_converted += 1
                
                # Extract HTTP flows
                http_file = analysis_dir / f"{pcap_file.stem}_http_flows.txt"
                extract_http_flows(str(pcap_file), str(http_file))
                
                # Generate summary
                summary_file = analysis_dir / f"{pcap_file.stem}_summary.txt"
                generate_pcap_summary(str(pcap_file), str(summary_file))
    
    print(f"\n✅ Conversion completed!")
    print(f"📊 Total pcap files processed: {total_files}")
    print(f"📊 Successfully converted: {total_converted}")
    print(f"💡 Analysis files saved in pcap_analysis/ subdirectories")

if __name__ == "__main__":
    convert_all_pcaps() 