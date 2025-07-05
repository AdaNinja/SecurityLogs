# Macro Attack Simulation Scripts

This directory contains three macro attack simulation scripts with varying levels of complexity and sophistication.

## Scripts Overview

### 1. Simple Variant (`macro_simulation_simple.py`)
- **Stealth Level**: Low
- **Obfuscation**: None
- **Execution Delay**: 0 seconds
- **Background Activities**: Minimal office work and web browsing
- **Attack Actions**: Basic command execution, file creation, system information gathering

### 2. Medium Variant (`macro_simulation_medium.py`)
- **Stealth Level**: Medium
- **Obfuscation**: Basic (Base64 encoding, simple encryption)
- **Execution Delay**: 5 seconds
- **Background Activities**: Moderate office work, collaboration, multimedia
- **Attack Actions**: Encrypted commands, registry modification, network connection, persistence

### 3. Complex Variant (`macro_simulation_complex.py`)
- **Stealth Level**: High
- **Obfuscation**: Advanced (multi-layer obfuscation, AES encryption, polymorphic code)
- **Execution Delay**: 15 seconds
- **Background Activities**: High-intensity office work, collaboration, multimedia, development, system maintenance
- **Attack Actions**: Polymorphic payload, anti-VM/sandbox evasion, advanced reconnaissance, persistence, lateral movement preparation

## Installation

1. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run any of the simulation scripts:

```bash
# Simple variant
python macro_simulation_simple.py

# Medium variant
python macro_simulation_medium.py

# Complex variant
python macro_simulation_complex.py
```

## What Each Script Does

### Background Activities
- **Office Work**: Creates and manipulates documents, performs file operations
- **Collaboration**: Simulates chat sessions, email composition, video meetings
- **Multimedia**: Simulates video streaming, music listening
- **Development**: Creates development files, simulates Git operations
- **System Maintenance**: Simulates system updates, backups, disk cleanup

### Attack Actions
- **Command Execution**: Runs system commands to gather information
- **File Operations**: Creates, reads, and modifies files
- **Network Activity**: Makes HTTP requests to simulate network communication
- **Persistence**: Creates scripts and mechanisms for persistence
- **Evasion**: Implements various anti-detection techniques

## Output Files

All scripts create various files in `/tmp/` directory to simulate real activity:
- Document files (`.txt`, `.json`)
- Configuration files
- Log files
- Persistence scripts
- Obfuscated content

## Security Note

These scripts are for educational and research purposes only. They simulate malicious behavior but do not perform actual harmful actions. Use only in controlled, isolated environments.

## Dependencies

- `requests`: For HTTP requests and network simulation
- `psutil`: For system information gathering and process monitoring
- Standard Python libraries: `subprocess`, `time`, `os`, `random`, `base64`, `hashlib`, `json`, `shutil`, `tempfile`, `threading`, `platform` 