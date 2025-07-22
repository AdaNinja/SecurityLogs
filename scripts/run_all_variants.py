#!/usr/bin/env python3
"""
Batch Variant Runner
Run all security experiment variants automatically
"""

import os
import sys
import subprocess
import argparse
import json
import time
from datetime import datetime
from pathlib import Path

def run_single_variant(variant_name, scenario_dir="scenarios/low-and-slow-sqli", skip_etl=False, max_retries=2,
                      interleaved=False, benign_mix="HTTP:0.6,DNS:0.3,SMTP:0.1", benign_duration=300):
    """Run a single variant with retry mechanism"""
    print(f"\n🎯 Running variant: {variant_name}")
    if interleaved:
        print("🔄 Mode: Interleaved (attack + benign traffic)")
    else:
        print("🎯 Mode: Attack only")
    print("=" * 60)
    
    for attempt in range(max_retries + 1):
        if attempt > 0:
            print(f"🔄 Retry attempt {attempt}/{max_retries} for {variant_name}")
            time.sleep(10)  # Wait before retry
        
        cmd = [
            "python3", "scripts/run_variant.py", 
            variant_name,
            "--scenario-dir", scenario_dir
        ]
        
        if skip_etl:
            cmd.append("--skip-etl")
        
        if interleaved:
            cmd.append("--interleaved")
            cmd.extend(["--benign-mix", benign_mix])
            cmd.extend(["--benign-duration", str(benign_duration)])
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"✅ {variant_name} completed successfully!")
            return True
        else:
            print(f"❌ {variant_name} failed (attempt {attempt + 1}):")
            print(result.stderr)
    
    print(f"💥 {variant_name} failed after {max_retries + 1} attempts")
    return False

def cleanup_between_variants():
    """Clean up between variant runs"""
    print("🧹 Cleaning up between variants...")
    
    # Stop all containers
    subprocess.run("docker-compose -f scenarios/low-and-slow-sqli/docker-compose.yml down", shell=True)
    
    # Remove any leftover networks
    subprocess.run("docker network prune -f", shell=True)
    
    # Wait a bit
    time.sleep(5)

def generate_experiment_summary(results, start_time):
    """Generate experiment summary report"""
    end_time = datetime.now()
    duration = end_time - start_time
    
    summary = {
        "experiment_start": start_time.isoformat(),
        "experiment_end": end_time.isoformat(),
        "duration_seconds": duration.total_seconds(),
        "variants": results,
        "success_count": sum(1 for r in results.values() if r),
        "total_count": len(results)
    }
    
    # Write summary to file
    timestamp = start_time.strftime("%Y%m%d_%H%M%S")
    summary_file = f"data/experiment_summary_{timestamp}.json"
    
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"\n📊 Experiment Summary saved to: {summary_file}")
    
    # Print summary
    print("\n" + "=" * 60)
    print("📈 EXPERIMENT SUMMARY")
    print("=" * 60)
    print(f"Start Time: {start_time}")
    print(f"End Time: {end_time}")
    print(f"Duration: {duration}")
    print(f"Success Rate: {summary['success_count']}/{summary['total_count']}")
    print("\nVariant Results:")
    
    for variant, success in results.items():
        status = "✅ SUCCESS" if success else "❌ FAILED"
        print(f"  {variant}: {status}")
    
    return summary

def main():
    parser = argparse.ArgumentParser(description="Run all security experiment variants")
    parser.add_argument("--scenario-dir", default="scenarios/low-and-slow-sqli",
                       help="Scenario directory path")
    parser.add_argument("--skip-etl", action="store_true",
                       help="Skip ETL processing for all variants")
    parser.add_argument("--max-retries", type=int, default=2,
                       help="Maximum retry attempts per variant")
    parser.add_argument("--variants", nargs="+", 
                       choices=["stealthy", "moderate", "aggressive"],
                       default=["stealthy", "moderate", "aggressive"],
                       help="Specific variants to run")
    parser.add_argument("--interleaved", action="store_true",
                       help="Run with interleaved benign traffic")
    parser.add_argument("--benign-mix", default="HTTP:0.6,DNS:0.3,SMTP:0.1",
                       help="Benign traffic protocol mix (e.g., HTTP:0.6,DNS:0.3,SMTP:0.1)")
    parser.add_argument("--benign-duration", type=int, default=300,
                       help="Benign traffic duration in seconds")
    
    args = parser.parse_args()
    
    print("🚀 Starting batch variant experiments")
    print(f"📋 Variants to run: {', '.join(args.variants)}")
    print(f"📁 Scenario directory: {args.scenario_dir}")
    print(f"🔄 Max retries per variant: {args.max_retries}")
    print(f"📊 Skip ETL: {args.skip_etl}")
    if args.interleaved:
        print(f"🔄 Interleaved mode: Enabled")
        print(f"🌐 Benign traffic mix: {args.benign_mix}")
        print(f"⏱️ Benign traffic duration: {args.benign_duration} seconds")
    else:
        print(f"🎯 Interleaved mode: Disabled (attack only)")
    print("=" * 60)
    
    start_time = datetime.now()
    results = {}
    
    try:
        for i, variant in enumerate(args.variants, 1):
            print(f"\n📊 Progress: {i}/{len(args.variants)}")
            
            # Clean up between variants (except for the first one)
            if i > 1:
                cleanup_between_variants()
            
            # Run the variant
            success = run_single_variant(
                variant, 
                args.scenario_dir, 
                args.skip_etl, 
                args.max_retries,
                args.interleaved,
                args.benign_mix,
                args.benign_duration
            )
            
            results[variant] = success
            
            # Add delay between variants
            if i < len(args.variants):
                print("⏳ Waiting 30 seconds before next variant...")
                time.sleep(30)
    
    except KeyboardInterrupt:
        print("\n⏹️  Experiment interrupted by user")
        results[variant] = False  # Mark current variant as failed
    
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        if variant:
            results[variant] = False
    
    # Generate summary
    summary = generate_experiment_summary(results, start_time)
    
    # Exit with appropriate code
    if summary['success_count'] == summary['total_count']:
        print("\n🎉 All variants completed successfully!")
        sys.exit(0)
    else:
        print(f"\n⚠️  {summary['total_count'] - summary['success_count']} variants failed")
        sys.exit(1)

if __name__ == "__main__":
    main() 