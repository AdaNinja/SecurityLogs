# CyberRange School Environment Setup

## 🚨 Quick Fix for "externally-managed-environment" Error

If you see this error:
```
error: externally-managed-environment
× This environment is externally managed
```

**Use this quick fix:**

```bash
# Option 1: Quick install (recommended)
./quick_install.sh

# Option 2: Manual user installation
pip3 install --user -r requirements-minimal.txt

# Option 3: Force system installation (risky)
pip3 install --break-system-packages -r requirements-minimal.txt
```

## 📋 System Requirements

### Python Environment
- **Python 3.8+** (you have 3.12.3 ✅)
- **pip3** (you have 24.0 ✅)

### Docker Environment (Optional for now)
- Docker is not required for basic functionality
- You can run scenarios without Docker containers

## 🚀 Installation Methods

### Method 1: Quick Install (Recommended)
```bash
./quick_install.sh
```

### Method 2: User Installation (Safest)
```bash
pip3 install --user -r requirements-minimal.txt
```

### Method 3: System Installation (Risky)
```bash
pip3 install --break-system-packages -r requirements-minimal.txt
```

### Method 4: System Packages (If available)
```bash
sudo apt install python3-docker python3-yaml python3-pandas python3-requests
```

## 🧪 Testing Installation

After installation, test if it works:

```bash
python3 -c "import docker, yaml, pandas, requests; print('✅ All dependencies OK')"
```

## 🎯 Running Scenarios

Once dependencies are installed:

```bash
# Run a test scenario
python3 run_scenario.py --config scenarios/test_multi_nodes.yaml

# Or run with dry-run first
python3 run_scenario.py --config scenarios/test_multi_nodes.yaml --dry-run
```

## 🔧 Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'docker'"
**Solution:** Run the quick install script:
```bash
./quick_install.sh
```

### Issue: "externally-managed-environment"
**Solution:** Use user installation:
```bash
pip3 install --user -r requirements-minimal.txt
```

### Issue: Permission denied
**Solution:** Use user installation or contact admin:
```bash
pip3 install --user -r requirements-minimal.txt
```

### Issue: Docker not found
**Solution:** Docker is optional. You can run scenarios without it, but some features may be limited.

## 📁 File Structure

After successful installation, you should have:
```
CyberRange/
├── requirements-minimal.txt    # Minimal dependencies
├── quick_install.sh           # Quick installation script
├── install_dependencies_school.sh  # Full installation script
├── run_scenario.py            # Main scenario runner
└── scenarios/                 # Scenario configurations
    └── test_multi_nodes.yaml  # Test scenario
```

## 🆘 Getting Help

If you still have issues:

1. **Check Python version**: `python3 --version`
2. **Check pip version**: `pip3 --version`
3. **Try minimal installation**: `pip3 install --user -r requirements-minimal.txt`
4. **Contact system administrator** for help with system packages

## 📝 Notes

- The `--user` flag installs packages to your home directory
- The `--break-system-packages` flag bypasses system protection (use with caution)
- Docker is optional but recommended for full functionality
- All scenarios can run without Docker, but with limited features
