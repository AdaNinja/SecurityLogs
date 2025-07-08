#!/usr/bin/env python3
"""
Configuration Loader for SecurityLogs
Loads variant configurations from YAML and converts to environment variables
"""

import yaml
import os
import sys
from pathlib import Path

class ConfigLoader:
    def __init__(self, config_dir="config"):
        self.config_dir = Path(config_dir)
        self.variants_file = self.config_dir / "variants.yml"
        self.variants = {}
        self.default_variant = "moderate"
        
    def load_variants(self):
        """Load variants configuration from YAML file"""
        try:
            with open(self.variants_file, 'r') as f:
                config = yaml.safe_load(f)
                
            self.variants = config.get('variants', {})
            self.default_variant = config.get('default_variant', 'moderate')
            
            print(f"Loaded {len(self.variants)} variants from {self.variants_file}")
            return True
            
        except Exception as e:
            print(f"Error loading variants: {e}")
            return False
    
    def get_variant_config(self, variant_name=None):
        """Get configuration for a specific variant"""
        if variant_name is None:
            variant_name = self.default_variant
            
        if variant_name not in self.variants:
            print(f"Variant '{variant_name}' not found. Available variants: {list(self.variants.keys())}")
            return None
            
        return self.variants[variant_name]
    
    def convert_to_env_vars(self, variant_config):
        """Convert variant configuration to environment variables"""
        env_vars = {}
        
        # Convert all nested config to environment variables
        for key, value in variant_config.items():
            if isinstance(value, list):
                # Convert lists to comma-separated strings
                env_vars[key.upper()] = ','.join(map(str, value))
            elif isinstance(value, bool):
                # Convert booleans to strings
                env_vars[key.upper()] = str(value).lower()
            else:
                # Convert everything else to string
                env_vars[key.upper()] = str(value)
        
        return env_vars
    
    def export_env_vars(self, variant_name=None):
        """Export variant configuration as environment variables"""
        variant_config = self.get_variant_config(variant_name)
        if not variant_config:
            return False
            
        env_vars = self.convert_to_env_vars(variant_config)
        
        # Export to environment
        for key, value in env_vars.items():
            os.environ[key] = value
            
        print(f"Exported {len(env_vars)} environment variables for variant '{variant_name or self.default_variant}'")
        return True
    
    def list_variants(self):
        """List all available variants"""
        if not self.variants:
            self.load_variants()
            
        print("Available variants:")
        for name, config in self.variants.items():
            description = config.get('description', 'No description')
            print(f"  {name}: {description}")
            
        print(f"\nDefault variant: {self.default_variant}")
    
    def list_variants_comparison(self):
        """List key differentiating parameters for all variants"""
        if not self.variants:
            self.load_variants()
            
        print("=== Variants Comparison (Key Differences) ===")
        
        # Key parameters that differentiate variants
        key_params = [
            'nmap_rate', 'nmap_timing', 'sql_delay', 
            'sqlmap_risk', 'sqlmap_level', 'sqlmap_threads',
            'protocol_mix', 'user_count', 'attack_duration'
        ]
        
        # Print header
        header = f"{'Variant':<12}"
        for param in key_params:
            header += f"{param:<12}"
        print(header)
        print("-" * len(header))
        
        # Print each variant's key parameters
        for variant_name, config in self.variants.items():
            row = f"{variant_name:<12}"
            for param in key_params:
                value = config.get(param)
                if value is not None:
                    if isinstance(value, list):
                        display_value = ','.join(map(str, value))
                    elif isinstance(value, bool):
                        display_value = str(value)
                    else:
                        display_value = str(value)
                    
                    # Truncate long values
                    if len(display_value) > 10:
                        display_value = display_value[:7] + "..."
                    row += f"{display_value:<12}"
                else:
                    row += f"{'N/A':<12}"
            print(row)
        
        print("\nLegend:")
        print("  SQLMap RISK: 1=Low, 2=Medium, 3=High")
        print("  SQLMap LEVEL: 1=Basic, 2=Extended, 3=Deep, 4=Comprehensive, 5=Extreme")
        print("  Nmap Timing: T0=Paranoid, T1=Sneaky, T2=Polite, T3=Normal, T4=Aggressive, T5=Insane")

def main():
    """Main function for command line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='SecurityLogs Configuration Loader')
    parser.add_argument('--variant', '-v', help='Variant name to load')
    parser.add_argument('--list', '-l', action='store_true', help='List available variants')
    parser.add_argument('--comparison', '-c', action='store_true', help='Show comparison of key parameters for all variants')
    parser.add_argument('--export', '-e', action='store_true', help='Export to environment variables')
    parser.add_argument('--config-dir', default='config', help='Configuration directory')
    
    args = parser.parse_args()
    
    loader = ConfigLoader(args.config_dir)
    
    if not loader.load_variants():
        sys.exit(1)
    
    if args.list:
        loader.list_variants()
        return
        
    if args.comparison:
        loader.list_variants_comparison()
        return
        
    if args.export:
        if not loader.export_env_vars(args.variant):
            sys.exit(1)
        return
    
    # Default: export to environment
    if not loader.export_env_vars(args.variant):
        sys.exit(1)

if __name__ == "__main__":
    main() 