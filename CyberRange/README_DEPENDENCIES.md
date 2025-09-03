# CyberRange Dependencies Installation Guide

## Quick Start

### Option 1: Automated Installation (Recommended)
```bash
# Install all dependencies automatically
./install_dependencies.sh

# Or install minimal dependencies only
./install_dependencies.sh --minimal
```

### Option 2: Manual Installation
```bash
# Install full dependencies
pip3 install -r requirements.txt

# Or install minimal dependencies only
pip3 install -r requirements-minimal.txt
```

## System Requirements

### Python Environment
- **Python 3.8+** (recommended: Python 3.9+)
- **pip3** package manager
- **Virtual environment** (recommended but not required)

### Docker Environment
- **Docker Engine 20.10+**
- **Docker Compose 2.0+**
- Docker daemon running

## Dependency Packages

### Core Dependencies (Required)
- `docker>=6.0.0` - Docker Python SDK for container management
- `PyYAML>=6.0` - YAML configuration file parsing
- `pandas>=1.5.0` - Data processing and CSV handling
- `requests>=2.28.0` - HTTP requests for web interactions
- `jsonpath-ng>=1.5.0` - JSON path processing for log analysis

### Additional Dependencies (Full Installation)
- `numpy>=1.21.0` - Numerical computing
- `urllib3>=1.26.0` - HTTP client library
- `psutil>=5.9.0` - System monitoring
- `scapy>=2.4.5` - Network packet analysis
- `python-dateutil>=2.8.0` - Date/time handling
- `regex>=2022.0.0` - Advanced regular expressions

## Installation Methods

### 1. Using Virtual Environment (Recommended)
```bash
# Create virtual environment
python3 -m venv cyberrange_env

# Activate virtual environment
source cyberrange_env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Deactivate when done
deactivate
```

### 2. Using Conda
```bash
# Create conda environment
conda create -n cyberrange python=3.9

# Activate environment
conda activate cyberrange

# Install dependencies
pip install -r requirements.txt
```

### 3. System-wide Installation
```bash
# Install system-wide (requires sudo)
sudo pip3 install -r requirements.txt
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied
```bash
# Use user installation
pip3 install --user -r requirements.txt
```

#### 2. Docker Module Not Found
```bash
# Ensure Docker is installed and running
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group
sudo usermod -aG docker $USER
# Log out and back in
```

#### 3. YAML Module Issues
```bash
# Install PyYAML specifically
pip3 install PyYAML
```

#### 4. Pandas Installation Issues
```bash
# Install system dependencies first (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install python3-dev python3-pip

# Then install pandas
pip3 install pandas
```

### Verification

After installation, verify all dependencies:
```bash
# Run the verification script
./install_dependencies.sh --verbose

# Or test manually
python3 -c "import docker, yaml, pandas, requests; print('All dependencies OK')"
```

## Development Dependencies

For development work, additional packages are available:
```bash
# Install development dependencies
pip3 install pytest pytest-cov black flake8

# Or uncomment in requirements.txt
```

## Platform-Specific Notes

### Ubuntu/Debian
```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install python3-dev python3-pip docker.io docker-compose

# Install Python packages
pip3 install -r requirements.txt
```

### CentOS/RHEL
```bash
# Install system dependencies
sudo yum install python3-devel python3-pip docker docker-compose

# Install Python packages
pip3 install -r requirements.txt
```

### macOS
```bash
# Install using Homebrew
brew install python3 docker docker-compose

# Install Python packages
pip3 install -r requirements.txt
```

## Support

If you encounter issues:
1. Check the troubleshooting section above
2. Verify your Python and Docker installations
3. Try the minimal installation first: `./install_dependencies.sh --minimal`
4. Check system logs for detailed error messages
