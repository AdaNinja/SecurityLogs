# CyberRange Automation Scripts

## Quick Start

### 1. Clean Environment
```bash
./scripts/clean.sh
```
Clear all logs, data, and containers

### 2. Run Experiments
```bash
python3 run_scenario.py --config scenarios/waf_off_demo.yaml
```
Run WAF OFF mode experiment

```bash
python3 run_scenario.py --config scenarios/waf_on_demo.yaml
```
Run WAF ON mode experiment

### 3. Parse Data
```bash
python3 parsers/parse_logs.py --input-dir logs --output-dir output --log-type all
```
Convert experiment data to CSV format

## Script Descriptions

- `clean.sh` - Clean environment, use before running new experiments 