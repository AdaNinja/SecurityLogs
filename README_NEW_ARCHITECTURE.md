# New Architecture Design - Configurable Attack Scenarios

## **Design Objectives**

1. **Realistic User Behavior**: Simulate real machine usage scenarios
2. **Configurable Variants**: Create different complexity scenarios through configuration files
3. **Single Host Implementation**: Start with single host, then expand to multiple hosts
4. **Detection Value**: Provide meaningful detection and analysis value

## **New Architecture Overview**

### **Directory Structure**
```
scenarios/
├── ssh_attack/
│   └── scenario.yaml          # SSH weak password attack configuration
├── redis_attack/
│   └── scenario.yaml          # Redis unauthorized access configuration
├── macro_attack/
│   └── scenario.yaml          # Macro document attack configuration
└── run_scenario.py            # Universal scenario execution script
```

### **Core Components**

1. **Scenario Configuration Files (YAML)**
   - Define attack types and parameters
   - Configure background activities
   - Set logging collection options

2. **Universal Execution Script (Python)**
   - Parse configuration files
   - Execute background activities
   - Run attack scenarios
   - Collect log data

## 📋 **Scenario Design**

### **1. SSH Weak Password Attack Scenario**

#### **Simple Variant**
- **Background Activities**: Basic file operations, simple network activities
- **Attack**: Fast SSH brute force
- **Complexity**: Low

#### **Complex Variant**
- **Background Activities**: Office work, multimedia, communication tools, development activities
- **Attack**: Slow, stealthy SSH brute force
- **Complexity**: High

### **2. Redis Unauthorized Access Scenario**

#### **Simple Variant**
- **Background Activities**: Web browsing, file operations
- **Attack**: Basic Redis command execution
- **Complexity**: Low

#### **Complex Variant**
- **Background Activities**: Development work, collaboration tools, multimedia, system maintenance
- **Attack**: Complex Redis exploitation chain
- **Complexity**: High

### **3. Macro Document Attack Scenario**

#### **Simple Variant**
- **Background Activities**: Basic office work, web browsing
- **Attack**: Simple macro document download and execution
- **Complexity**: Low

#### **Complex Variant**
- **Background Activities**: Intensive office work, collaboration tools, multimedia, development work
- **Attack**: Social engineering + complex macro documents
- **Complexity**: High

## 🔧 **Usage Instructions**

### **Running Scenarios**
```bash
# Run simple variant
python run_scenario.py scenarios/ssh_attack/scenario.yaml simple

# Run complex variant
python run_scenario.py scenarios/ssh_attack/scenario.yaml complex

# Run Redis attack
python run_scenario.py scenarios/redis_attack/scenario.yaml complex

# Run macro document attack
python run_scenario.py scenarios/macro_attack/scenario.yaml complex
```

### **Configuration File Example**
```yaml
name: "ssh_weak_password_attack"
description: "SSH brute force attack scenario"

variants:
  simple:
    name: "Simple Variant"
    background_activities:
      - type: "file_operations"
        actions: ["create_temp_files", "browse_documents"]
    
    attack:
      type: "ssh_bruteforce"
      target: "localhost:22"
      username_list: ["root", "admin"]
      password_list: ["password", "123456"]
      attempts_per_second: 2
```

## 🎯 **Improvements Meeting Professor's Requirements**

### **1. Realistic User Behavior**
- ✅ **Office Activities**: Document editing, emails, spreadsheet analysis
- ✅ **Multimedia**: Video watching, music playing, video conferencing
- ✅ **Communication Tools**: Slack, Teams, Zoom
- ✅ **Development Work**: Code editing, testing, Git operations
- ✅ **System Activities**: Updates, backups, cleanup

### **2. Configurable Variants**
- ✅ **Simple Variant**: Minimal background activity, obvious attack
- ✅ **Complex Variant**: Rich background activity, stealthy attack
- ✅ **Configuration Driven**: Control behavior through YAML files

### **3. Detection Value**
- ✅ **Mixed Traffic**: Normal activity + malicious activity
- ✅ **Temporal Analysis**: Attack timing within normal activities
- ✅ **Behavior Patterns**: Different complexity behavior differences
- ✅ **Rich Logging**: Multiple types of log data

### **4. Single Host Implementation**
- ✅ **Independent Operation**: Each scenario can run independently
- ✅ **Easy Expansion**: Can be extended to multiple hosts later
- ✅ **Resource Friendly**: Low resource requirements for single host

## 📊 **Data Collection**

### **Log Types**
- **System Logs**: Process creation, file access, network connections
- **Application Logs**: SSH, Redis, Office applications
- **Network Logs**: PCAP traffic data
- **Behavior Logs**: User operations, application usage

### **Data Labeling**
- **Attack Markers**: Attack start/end times
- **Behavior Markers**: Normal/anomalous behavior
- **Variant Markers**: Simple/complex variant identification

## 🚀 **Implementation Plan**

### **Phase 1 (This Week)**
1. ✅ Complete three scenario configuration files
2. ✅ Implement universal execution script
3. 🔄 Implement specific attack logic
4. 🔄 Improve background activity simulation

### **Phase 2**
1. Add more scenario variants
2. Implement more complex background activities
3. Optimize log collection mechanism
4. Add data analysis tools

### **Phase 3**
1. Extend to multi-host environment
2. Implement distributed scenarios
3. Add machine learning detection
4. Complete documentation and reports

## 🎯 **Expected Results**

### **Challenges for Detection Systems**
- **Noisy Environment**: Rich background activities increase detection difficulty
- **Temporal Complexity**: Natural attack timing within normal activities
- **Behavior Diversity**: Different variant behavior patterns

### **Value for Analysis**
- **Realistic Scenarios**: Attack scenarios close to real environments
- **Reproducibility**: Configuration-driven reproducible experiments
- **Comparative Analysis**: Simple vs complex variant comparison

This new architecture fully meets the professor's requirements, providing realistic, configurable, and valuable attack scenarios for security research and machine learning high-quality datasets. 