# Variant-Specific PCAP File Generation

This document explains how to use the new variant-specific PCAP file generation feature to avoid dataset contamination.

## Overview

The new system generates separate PCAP files for each attack variant, ensuring that different attack scenarios don't mix together in the same capture file.

## File Naming Convention

PCAP files follow this naming pattern:
```
${SCENARIO_NAME}_${VARIANT}_${TIMESTAMP}.pcap
```

Example files:
- `low-and-slow-sqli_stealthy_20240601_143022.pcap`
- `low-and-slow-sqli_moderate_20240601_143156.pcap`
- `low-and-slow-sqli_aggressive_20240601_143245.pcap`

## Available Variants

From `variants.yml`, the following variants are supported:
- `stealthy` - Very slow and stealthy attack (RISK=1, LEVEL=1)
- `moderate` - Balanced attack (RISK=1, LEVEL=2)
- `aggressive` - Faster attack (RISK=2, LEVEL=3)
- `research` - Research-focused variant (RISK=1, LEVEL=4)
- `production` - Production-like environment (RISK=1, LEVEL=2)

## Usage

### 1. Individual Variant Experiments

Use the `variant_experiment.sh` script for individual variant experiments:

```bash
# Start PCAP capture for stealthy variant
./scripts/variant_experiment.sh stealthy

# Start with custom timestamp
./scripts/variant_experiment.sh moderate -t 20240601_143022

# Stop a specific experiment
./scripts/variant_experiment.sh --stop stealthy 20240601_143022

# List available variants
./scripts/variant_experiment.sh -l

# List running experiments
./scripts/variant_experiment.sh --list-running
```

### 2. Batch Experiments with Interleaved Script

The `interleaved_attack.sh` script has been updated to automatically use variant-specific PCAP capture:

```bash
# Run all variants with separate PCAP files
./scripts/interleaved_attack.sh --attack-variants stealthy,moderate,aggressive

# Run with specific intensity
./scripts/interleaved_attack.sh --attack-intensity high

# Run multi-dataset collection
./scripts/interleaved_attack.sh --multi-dataset
```

### 3. Testing the Functionality

Test the new functionality without running full attacks:

```bash
./scripts/test_variant_pcap.sh
```

## How It Works

1. **Container Isolation**: Each variant gets its own tcpdump container with a unique name
2. **Dynamic Filename**: PCAP files are named using scenario name, variant name, and timestamp
3. **Automatic Cleanup**: Containers are automatically stopped and removed after each experiment
4. **Data Collection**: All variant-specific PCAP files are collected in the experiment output directory

## File Locations

- **PCAP Files**: `../../data/pcap/`
- **Experiment Output**: `../../data/output/interleaved/YYYYMMDD_HHMMSS/`
- **Container Logs**: `../../data/logs/`

## Integration with Existing Workflow

The new system is backward compatible:
- Legacy `traffic.pcap` files are still generated
- Existing scripts continue to work
- New variant-specific files are additional, not replacements

## Benefits

1. **No Dataset Contamination**: Each variant's traffic is captured separately
2. **Easy Analysis**: Clear file naming makes it easy to identify which variant generated which traffic
3. **Flexible Experiments**: Can run individual variants or batch experiments
4. **Timestamp Tracking**: Each experiment is timestamped for easy tracking
5. **Automatic Management**: Containers are automatically started and stopped

## Troubleshooting

### Common Issues

1. **Container Name Conflicts**: If you see "container name already in use" errors, clean up old containers:
   ```bash
   docker ps -a --filter "name=tcpdump-" | xargs docker rm -f
   ```

2. **Permission Issues**: Ensure the PCAP directory is writable:
   ```bash
   sudo chown -R $USER:$USER ../../data/pcap
   ```

3. **Missing PCAP Files**: Check if containers are running:
   ```bash
   docker ps --filter "name=tcpdump-"
   ```

### Debug Commands

```bash
# Check running tcpdump containers
docker ps --filter "name=tcpdump-"

# View container logs
docker logs tcpdump-{variant}-{timestamp}

# Check PCAP file sizes
ls -la ../../data/pcap/*.pcap

# Test variant script
./scripts/variant_experiment.sh -l
```

## Example Workflow

1. **Start Experiment**:
   ```bash
   cd scenarios/low-and-slow-sqli
   ./scripts/interleaved_attack.sh --attack-variants stealthy,moderate
   ```

2. **Monitor Progress**:
   ```bash
   ./scripts/variant_experiment.sh --list-running
   ```

3. **Check Results**:
   ```bash
   ls -la ../../data/pcap/low-and-slow-sqli_*.pcap
   ```

4. **Analyze Data**:
   ```bash
   tcpdump -r ../../data/pcap/low-and-slow-sqli_stealthy_*.pcap -c 50
   ```

This system ensures that your security research datasets remain clean and properly organized for analysis. 