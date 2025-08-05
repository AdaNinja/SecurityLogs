# User-Friendly Configuration System

## Overview

You can now define security experiments through simple YAML configuration without understanding technical details.

## Configuration Options

### 1. Attack Type Selection

In `scenarios/modular_demo_detailed.yaml`, you can specify which attack types to test:

```yaml
scenario:
  # ... other configurations ...
  attack_types: ["sql_injection", "xss"]  # Attack types to test
  waf_mode: "off"  # WAF mode: on/off/auto
```

**Supported Attack Types:**
- `sql_injection` - SQL Injection attacks
- `xss` - Cross-Site Scripting attacks
- `directory_traversal` - Directory Traversal attacks
- `command_injection` - Command Injection attacks
- `authentication_bypass` - Authentication Bypass attacks

**WAF Modes:**
- `on` - Enable WAF evasion mode
- `off` - Disable WAF evasion mode
- `auto` - Auto-detect WAF and adjust strategy

### 2. Experiment Control

```yaml
scenario:
  random_seed: 12345  # Ensure benign traffic reproducibility
  duration: 300       # Experiment duration (seconds)
```

**Random Seed Functionality:**
- Controls benign traffic random behaviors (user actions, session IDs, etc.)
- Attack execution order remains deterministic for consistency
- Ensures same configuration produces same benign traffic patterns
- Facilitates debugging and issue reproduction

### 3. Running Experiments

Use the existing run methods:

```bash
# Clean environment
./scripts/clean.sh

# Run experiment
python3 run_scenario.py

# Parse logs
python3 parsers/parse_logs.py
```

## How It Works

1. **Configuration Parsing** - System reads `attack_types` and `waf_mode` from YAML config
2. **Parameter Passing** - These parameters are passed to attack scripts
3. **Smart Filtering** - Attack scripts filter payloads based on parameters
4. **Reproducibility** - Use `random_seed` to ensure consistent benign traffic

## Example Configuration

```yaml
scenario:
  name: "web-security-test"
  description: "Web Application Security Test"
  duration: 300
  random_seed: 12345
  attack_types: ["sql_injection", "xss", "directory_traversal"]
  waf_mode: "auto"
```

## Benefits

✅ **Easy to Use** - Just select attack types in YAML  
✅ **Reproducible** - Use random seed to ensure benign traffic consistency  
✅ **Flexible Configuration** - Support WAF mode switching  
✅ **Backward Compatible** - No impact on existing functionality  
✅ **No Learning Required** - Hide technical details, focus on business logic  

## Notes

- Attack types must match those in the attack file
- WAF mode affects payload selection strategy
- Random seed ensures same benign traffic patterns with same configuration
- All existing functionality remains unchanged 