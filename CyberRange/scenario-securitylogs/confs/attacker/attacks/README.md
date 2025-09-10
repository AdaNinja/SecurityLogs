# CyberRange Attack Payloads Architecture

## 📁 Directory Structure

```
attacks/
├── README.md                           # This file
├── unified_attack_payloads.txt         # Basic payloads for all attack types
├── advanced_attack_chains.txt          # Multi-phase advanced attack chains
├── lateral_movement_techniques.txt     # Lateral movement specific payloads
├── sql_injection/                      # SQL injection category
│   ├── basic_sqli.txt                 # Basic SQL injection techniques
│   ├── union_sqli.txt                 # Union-based SQL injection
│   └── blind_sqli.txt                 # Blind SQL injection techniques
├── xss/                               # Cross-site scripting category
│   ├── reflected_xss.txt              # Reflected XSS payloads
│   └── stored_xss.txt                 # Stored/Persistent XSS payloads
├── command_injection/                  # Command injection category
│   ├── basic_cmd.txt                  # Basic command injection
│   └── reverse_shells.txt             # Reverse shell payloads
├── directory_traversal/               # Directory traversal attacks
├── auth_bypass/                       # Authentication bypass techniques
├── file_discovery/                    # File and information discovery
└── method_enumeration/                # HTTP method enumeration
```

## 🚀 Usage

### Basic Usage

The `unified_attack.sh` script automatically detects and loads category-specific payloads:

```bash
# Use all SQL injection payloads from the sql_injection/ directory
./unified_attack.sh --mode basic --type sql_injection

# Use specific attack category
./unified_attack.sh --mode basic --type xss

# Use all attack types from unified_attack_payloads.txt
./unified_attack.sh --mode basic --type all
```

### Advanced Usage

```bash
# Use advanced multi-phase attack chains
./unified_attack.sh --mode advanced

# Use custom payload file
./unified_attack.sh --mode custom --file /path/to/custom_payloads.txt
```

## 📝 Payload File Format

All payload files follow this format:
```
method|endpoint|payload|expected_code|attack_id|description
```

Example:
```
POST|/rest/user/login|{"email":"' OR '1'='1' --","password":"any"}|401|sqli_basic_001|Classic OR 1=1
```

## 🔧 Managing Payloads

Use the `manage_payloads.sh` script to manage and view payloads:

```bash
# List all categories and payload counts
./manage_payloads.sh list

# Show details for a specific category
./manage_payloads.sh show sql_injection

# Count total payloads
./manage_payloads.sh count

# Test if category can be loaded
./manage_payloads.sh test xss
```

## ➕ Adding New Payloads

### To add payloads to an existing category:

1. Navigate to the category directory (e.g., `sql_injection/`)
2. Add your payloads to an existing file or create a new `.txt` file
3. Follow the standard format

### To create a new attack category:

1. Create a new directory: `mkdir new_attack_type`
2. Create payload files inside: `new_attack_type/payloads.txt`
3. The `unified_attack.sh` will automatically detect and use them

## 📊 Current Payload Statistics

- **SQL Injection**: 45+ payloads across 3 files
- **XSS**: 40+ payloads across 2 files  
- **Command Injection**: 40+ payloads across 2 files
- **Advanced Chains**: 25+ multi-phase attack sequences
- **Lateral Movement**: 15+ techniques

## 🎯 Attack Categories

### SQL Injection (`sql_injection/`)
- Basic injection techniques
- Union-based attacks
- Blind injection (boolean & time-based)
- Error-based extraction
- Second-order injection

### Cross-Site Scripting (`xss/`)
- Reflected XSS
- Stored/Persistent XSS
- DOM-based XSS
- Filter bypass techniques
- Polyglot payloads

### Command Injection (`command_injection/`)
- Basic command execution
- Command chaining
- Reverse shells (multiple languages)
- File operations
- Privilege escalation

### Directory Traversal (`directory_traversal/`)
- Path traversal
- File inclusion
- Directory listing

### Authentication Bypass (`auth_bypass/`)
- SQL injection auth bypass
- Default credentials
- Session manipulation

### File Discovery (`file_discovery/`)
- Common file paths
- Backup file discovery
- Configuration file search

### Method Enumeration (`method_enumeration/`)
- HTTP method testing
- Verb tampering
- Method override techniques

## 🔍 Tips

1. **Testing**: Always test payloads in a controlled environment first
2. **Customization**: Modify payloads to match your target application
3. **Encoding**: Some payloads may need URL encoding depending on the context
4. **Rate Limiting**: Use appropriate intervals between attacks to avoid detection
5. **Logging**: All attacks are logged with detailed information for analysis

## ⚠️ Disclaimer

These payloads are for authorized security testing only. Always ensure you have proper permission before testing any system.
