# Macro Attack Simulation Scripts - Improvements Summary

## Overview

We have successfully improved the three macro attack simulation scripts to actually execute background activities and attack activities, rather than just printing information. All output files are now saved in the project directory for easy viewing and management.

## Major Improvements

### 1. Real Activity Execution
- **Background Activities**: Create real documents, chat logs, emails, multimedia metadata, etc.
- **Attack Activities**: Execute system commands, create files, network connections, persistence mechanisms, etc.
- **Obfuscation Techniques**: Implement real Base64 encoding, multi-layer obfuscation, polymorphic code generation

### 2. Output File Management
- All files are now saved in the project directory's `output/` subdirectory
- Each script has its own output directory:
  - `output/simple/` - Simple version
  - `output/medium/` - Medium version  
  - `output/complex/` - Complex version

### 3. Script Functionality Comparison

#### Simple Version
- **Background Activities**: Minimal office work and web browsing
- **Attack Activities**: Basic command execution, file creation, system information gathering
- **Output Files**: 6 files (documents, backups, persistence files, etc.)

#### Medium Version
- **Background Activities**: Moderate office work, collaboration, multimedia activities
- **Attack Activities**: Encrypted commands, registry modification, network connections, persistence
- **Obfuscation Techniques**: Base64 encoding, simple encryption, social engineering
- **Output Files**: 16 files (documents, chats, emails, obfuscated content, etc.)

#### Complex Version
- **Background Activities**: High-intensity office work, collaboration, multimedia, development, system maintenance
- **Attack Activities**: Polymorphic payloads, anti-analysis checks, advanced reconnaissance, persistence, lateral movement preparation
- **Obfuscation Techniques**: Multi-layer obfuscation, AES encryption, polymorphic code, anti-VM/sandbox detection
- **Output Files**: 50+ files (complex documents, chat sessions, development files, obfuscated content, etc.)

## File Structure

```
scenarios/macro_attack/
├── macro_simulation_simple.py
├── macro_simulation_medium.py
├── macro_simulation_complex.py
├── requirements.txt
├── README.md
└── output/
    ├── simple/
    │   ├── test_document.txt
    │   ├── test_document_backup.txt
    │   ├── macro_test_simple.txt
    │   └── macro_persistence_*.txt
    ├── medium/
    │   ├── project_proposal.txt
    │   ├── slack_chat.txt
    │   ├── draft_email.txt
    │   ├── obfuscated_macro.txt
    │   ├── encrypted_macro.key
    │   ├── social_engineering.json
    │   ├── registry_modification.json
    │   └── macro_persistence.sh
    └── complex/
        ├── quarterly_report.txt
        ├── general_chat.txt
        ├── zoom_meeting.json
        ├── advanced_obfuscated.txt
        ├── advanced_encryption.json
        ├── polymorphic_code.py
        ├── anti_analysis_results.json
        ├── system_reconnaissance.json
        ├── persistence_*.sh
        └── lateral_movement.json
```

## Technical Features

### Background Activity Simulation
- **Office Work**: Create and edit documents, file operations, backups
- **Collaboration Activities**: Slack chats, Zoom meetings, email composition
- **Multimedia**: Video streaming, music playback, playlists
- **Development Activities**: Code files, configuration files, Git operations
- **System Maintenance**: System updates, backups, disk cleanup

### Attack Activity Implementation
- **Command Execution**: `whoami`, `hostname`, `uname -a`
- **File Operations**: Create, read, modify files
- **Network Activities**: HTTP requests, IP information retrieval
- **Persistence**: Create executable scripts, registry modifications
- **Obfuscation Techniques**: Base64 encoding, XOR encryption, multi-layer obfuscation
- **Anti-Analysis**: VM detection, sandbox detection, process monitoring

### Advanced Features
- **Polymorphic Code**: Dynamic code generation and execution
- **Anti-Detection**: Detect analysis environments and virtual machines
- **Social Engineering**: Psychological analysis, urgency settings
- **Lateral Movement**: Network mapping, credential dumping preparation

## Usage Instructions

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run scripts:
```bash
# Simple version
python3 macro_simulation_simple.py

# Medium version
python3 macro_simulation_medium.py

# Complex version
python3 macro_simulation_complex.py
```

3. View output:
```bash
# View simple version output
ls -la output/simple/

# View medium version output
ls -la output/medium/

# View complex version output
ls -la output/complex/
```

## Security Notice

These scripts are for educational and research purposes only, simulating malicious behavior without executing actual harmful operations. Please use in controlled, isolated environments.

## Dependencies

- `requests`: HTTP requests and network simulation
- `psutil`: System information collection and process monitoring
- Standard Python libraries: `subprocess`, `time`, `os`, `random`, `base64`, `hashlib`, `json`, `shutil`, `tempfile`, `threading`, `platform` 