# CyberRange - Security Training Environment

A platform for application-layer attack simulation and multi-source log analysis.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run experiment
python run_scenario.py --config scenarios/waf_on_demo.yaml

# Clean environment
./scripts/clean.sh
```

## Features

- **Reproducible**: Same configuration produces consistent results
- **Configurable**: Define scenarios via YAML files
- **Extensible**: Support for multiple attack types
- **Modular**: Easy to maintain and extend

## License

MIT License - For security research and educational purposes only.

