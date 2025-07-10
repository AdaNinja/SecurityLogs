# Control Center

This directory contains control scripts and automation tools for the SecurityLogs project.

## Directory Structure

### `network/` - Network Emulation Tools
Network condition simulation and management scripts.

- **`apply_netem.sh`** - Apply network conditions (latency, packet loss, etc.)
- **`reset_netem.sh`** - Reset network conditions to normal
- **`netem_profiles/`** - Network condition configuration profiles

### `automation/` - Automation Scripts
Automated experiment execution and data collection scripts.

- **`run_all_variants.sh`** - Execute all attack variants with data collection
- **`capture.sh`** - Complete traffic capture and analysis workflow
- **`multi_source_logger.py`** - Multi-source log collection and analysis

## Usage Examples

### Network Emulation
```bash
# Apply network conditions
bash control/network/apply_netem.sh --profile low_latency

# Reset network conditions
bash control/network/reset_netem.sh
```

### Automation
```bash
# Run all attack variants
bash control/automation/run_all_variants.sh

# Complete capture workflow
bash control/automation/capture.sh

# Multi-source log analysis
python3 control/automation/multi_source_logger.py
```

## Integration with Makefile

The main Makefile provides convenient targets that use these scripts:

```bash
make apply-netem    # Uses control/network/apply_netem.sh
make reset-netem    # Uses control/network/reset_netem.sh
make interleaved    # Uses control/automation/run_all_variants.sh
make collect-logs   # Uses control/automation/multi_source_logger.py
``` 