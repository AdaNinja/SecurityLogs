# SecurityLogs Project Progress Report
**Report Date**: July 11, 2025  
**Presenter**: Jiayi  
**Project Phase**: Multi-source Log Data Collection Experiment Preparation  

## Project Overview

### Research Objective
Build a containerized security log dataset generation platform for collecting multi-source log data, providing high-quality datasets for subsequent machine learning model training and attack detection research.

### Core Value
- **Multi-source Data Collection**: Container logs, application logs, network traffic, attack tool logs
- **Controlled Experimental Environment**: Docker containerization ensuring experiment reproducibility
- **Realistic Attack Scenarios**: Simulating real SQL injection attacks with benign traffic mixing
- **Standardized Data Format**: Providing unified data structure for subsequent labeling work

## Completed Work

### 1. Project Architecture Design ✅
```
SecurityLogs/
├── containers/          # Container definitions (webapp, attacker, tcpdump)
├── control/            # Control center (network simulation, automation scripts)
├── scenarios/          # Attack scenarios (SQL injection)
├── data/              # Data storage (logs, PCAP, analysis results)
└── docs/              # Project documentation
```

### 2. Containerized Environment Setup ✅
- **Webapp Container**: Vulnerable web application (Nginx + PHP + MySQL)
- **Attacker Container**: Attack execution environment (SQLMap, Nmap, Python tools)
- **Tcpdump Container**: Network traffic capture and analysis
- **Log-aggregator Container**: Multi-source log collection and aggregation

### 3. Attack Scenario Implementation ✅
**SQL Injection Attack Scenario**:
- Three attack intensity variants (Stealthy, Moderate, Aggressive)
- Based on official SQLMap RISK/LEVEL parameters
- Interleaved benign and malicious traffic
- Network condition simulation (low/medium/high latency)

### 4. Automation Tool Development ✅
- **Unified Management**: Makefile providing convenient project management
- **Network Simulation**: Configurable network condition application
- **Batch Execution**: Support for parallel and sequential experiment execution
- **Data Collection**: Multi-source log automatic collection and analysis

### 5. Project Documentation Completion ✅
- **Installation Configuration**: Detailed system requirements and installation guide
- **Usage Instructions**: Complete usage workflow and examples
- **Troubleshooting**: Common problems and solutions
- **Project Structure**: Clear code organization documentation

## Current Experimental Design

### Data Collection Strategy
**Multi-source Log Types**:
1. **Container Logs**: Docker container system logs
2. **Application Logs**: Nginx, PHP, MySQL application logs
3. **Network Logs**: PCAP files, network traffic analysis
4. **Attack Logs**: SQLMap, Nmap and other tool logs
5. **System Logs**: Host system logs

### Experimental Variant Design
**Attack Intensity Variants**:
- Stealthy: RISK=1, LEVEL=1 (very slow attack)
- Moderate: RISK=1, LEVEL=2 (balanced attack)
- Aggressive: RISK=2, LEVEL=3 (faster attack)

**Network Condition Variants**:
- Low latency: 5ms
- Medium latency: 50ms
- High latency: 200ms

**Traffic Mix Variants**:
- HTTP dominant: 80% HTTP, 15% DNS, 5% SMTP
- Balanced mix: 70% HTTP, 20% DNS, 10% SMTP
- DNS dominant: 60% HTTP, 25% DNS, 15% SMTP

### Data Organization Structure
```
data/
├── logs/              # Application and container logs
├── pcap/              # Network traffic captures
└── output/            # Analysis results and reports
    └── variants/      # Results categorized by variants
```

## Technical Highlights

### 1. Modular Design
- **Container Decoupling**: Each container developed and tested independently
- **Script Modularization**: Automation scripts categorized by function
- **Configuration Separation**: Scenario configuration separated from implementation code

### 2. Scalable Architecture
- **New Scenario Addition**: Follow existing structure to add new attack scenarios
- **New Container Integration**: Standardized container definitions and configurations
- **New Tool Support**: Flexible automation script framework

### 3. Data Quality Control
- **Integrity Checks**: Log file size and line count verification
- **Timestamp Alignment**: Multi-source data time synchronization
- **Metadata Management**: Complete experiment parameter and result records

## Next Steps

### Short-term Goals (1-2 weeks)
1. **Execute Complete Experiments**: Run all attack variant combinations
2. **Data Collection**: Collect complete multi-source log dataset
3. **Data Validation**: Check data quality and integrity
4. **Preliminary Analysis**: Generate basic data analysis reports

### Medium-term Goals (2-4 weeks)
1. **Data Labeling**: Add labels to collected data
2. **Format Standardization**: Unify data format for machine learning use
3. **Dataset Construction**: Build training/validation/test datasets
4. **Baseline Model**: Train basic attack detection model

### Long-term Goals (1-2 months)
1. **Model Optimization**: Improve attack detection algorithms
2. **New Scenario Expansion**: Add more attack types
3. **Paper Writing**: Summarize research results
4. **Open Source Release**: Open source the project for community use

## Technical Challenges and Solutions

### Challenge 1: Multi-source Data Synchronization
**Problem**: Different container log timestamps may not be synchronized
**Solution**: Use unified time source and NTP synchronization

### Challenge 2: Data Volume Management
**Problem**: PCAP files and log files may be very large
**Solution**: Implement data compression and regular cleanup mechanisms

### Challenge 3: Experiment Reproducibility
**Problem**: Ensure consistency and reproducibility of experimental results
**Solution**: Fixed random seeds, version control for all configurations

## Expected Outcomes

### Dataset Scale
- **Experimental Variants**: 9 combinations (3 attacks × 3 network conditions)
- **Data Volume**: Expected 100MB-1GB data per variant
- **Total Data Volume**: Expected 5-10GB multi-source log data

### Data Quality
- **Completeness**: 100% experimental data collection
- **Consistency**: Standardized data format
- **Traceability**: Complete experimental metadata records

### Research Value
- **Realistic Scenarios**: Data based on real attack tools
- **Multi-dimensional**: Network, application, system multi-level data
- **Scalable**: Support rapid addition of new attack scenarios

## Summary

The project has completed basic architecture setup and experimental environment preparation, possessing the capability to conduct large-scale multi-source log data collection. The next step will be to execute the complete experimental process, collect high-quality datasets, and lay the foundation for subsequent machine learning research.

**Project Status**: Ready to begin data collection experiments  
**Risk Assessment**: Low risk, mature technical solution  
**Timeline**: Proceeding as planned, expected to complete data collection within 2 weeks 