# CyberRange Scenario Configuration Guide

## 📋 Scenario Overview

CyberRange provides 6 pre-configured scenarios to meet different testing and research needs:

| Scenario | Purpose | Duration | Attack Ratio | Features |
|----------|---------|----------|--------------|----------|
| `test_all_features` | Feature Validation | 10 min | 90% | Quick validation of all attack types |
| `test_multi_nodes` | Multi-node Testing | 15 min | 80% | Distributed attack testing |
| `balanced_ml_dataset` | ML Dataset | 30 min | 50% | Balanced training data |
| `realistic_production` | Production Simulation | 24 hours | 4.5% | Real environment simulation |
| `stress_test` | Stress Testing | 1 hour | 95% | High-intensity attack testing |
| `apt_simulation` | APT Simulation | 2 hours | 30% | Advanced Persistent Threat |

---

## 🎯 Detailed Scenario Descriptions

### 1. **test_all_features** - Feature Validation
```yaml
duration: 600s (10 minutes)
```
**Purpose**: Quick validation of all system functionalities
- ✅ **7 Basic Attacks**: SQL injection, XSS, command injection, directory traversal, auth bypass, file discovery, HTTP method enumeration
- ✅ **Advanced Multi-stage Attacks**: APT attack chain simulation
- ✅ **Attack Verification**: Strict validation of each attack's execution effectiveness
- 🎯 **Use Cases**: Development testing, feature validation, CI/CD integration

### 2. **test_multi_nodes** - Multi-node Testing
```yaml
duration: 900s (15 minutes)
```
**Purpose**: Test distributed attacks and multi-node coordination
- 🌐 **Multiple Attack Sources**: 3 attack nodes executing concurrently
- 🎯 **Multiple Targets**: Simultaneous attacks on multiple services
- 📊 **Load Balancing**: Test system performance under multi-node scenarios
- 🎯 **Use Cases**: Distributed system testing, load testing

### 3. **balanced_ml_dataset** - Machine Learning Dataset
```yaml
duration: 1800s (30 minutes)
```
**Purpose**: Generate balanced machine learning training data
- ⚖️ **Attack/Benign Ratio**: 50%/50%, avoiding class imbalance
- 📈 **Diversity**: Sufficient samples of all attack types
- 🏷️ **Complete Labels**: Precise Ground Truth labels
- 🎯 **Use Cases**: ML model training, algorithm research, academic studies

### 4. **realistic_production** - Production Environment Simulation
```yaml
duration: 86400s (24 hours)
```
**Purpose**: Simulate real production environment traffic patterns
- 🏭 **Realistic Ratio**: 4.5% attack traffic, 95.5% normal traffic
- 🛡️ **WAF Enabled**: Simulate real protection environment
- ⏰ **Long-term Operation**: 24-hour continuous monitoring
- 🎯 **Use Cases**: Production environment testing, long-term monitoring, realism validation

### 5. **stress_test** - Stress Testing
```yaml
duration: 3600s (1 hour)
```
**Purpose**: Test system performance under high attack loads
- 💥 **High Attack Density**: 95% attack traffic
- ⚡ **High Frequency**: Short-interval continuous attacks
- 🔥 **Stress Limits**: Test system capacity limits
- 🎯 **Use Cases**: Performance testing, capacity planning, stability validation

### 6. **apt_simulation** - APT Attack Simulation
```yaml
duration: 7200s (2 hours)
```
**Purpose**: Simulate Advanced Persistent Threat attacks
- 🎭 **Stealth**: Low-frequency, long-duration attack patterns
- 🔗 **Attack Chain**: Complete multi-stage attack sequences
- 🕵️ **Persistence**: Simulate APT persistence characteristics
- 🎯 **Use Cases**: APT detection, advanced threat research, security analysis

---

## 🚀 Quick Start

### Launch Scenarios
```bash
# Feature validation (recommended for beginners)
python3 run_scenario.py --config scenarios/test_all_features.yaml

# ML dataset generation
python3 run_scenario.py --config scenarios/balanced_ml_dataset.yaml

# Production environment simulation
python3 run_scenario.py --config scenarios/realistic_production.yaml
```

### Selection Guide
- 🔰 **First-time Use**: `test_all_features` - Quick system functionality validation
- 🤖 **Machine Learning**: `balanced_ml_dataset` - Generate balanced training data
- 🏭 **Production Testing**: `realistic_production` - Real environment simulation
- 💪 **Performance Testing**: `stress_test` - Extreme stress testing
- 🎯 **Security Research**: `apt_simulation` - Advanced threat analysis

---

## 📊 Output Data

Each scenario generates:
- 📝 **Raw Logs**: `logs/scenario_name_timestamp/`
- 📊 **Parsed Data**: `output/scenario_name_timestamp/`
- 📈 **Evaluation Reports**: `evaluation_results/scenario_name_timestamp/`

### Core Output Files
- `nginx_detailed.csv` - Web access logs
- `network_traffic.csv` - Network traffic records
- `attack_consolidated.csv` - Attack event summary
- `precise_labels_precise_labels.csv` - Precise label data

---

## ⚙️ Custom Configuration

### Modify Attack Ratios
```yaml
traffic_patterns:
  attack_traffic:
    - name: sql_injection
      percentage: 0.15  # Adjust to 15%
```

### Modify Duration
```yaml
scenario:
  duration: 1200  # Change to 20 minutes
```

### Enable/Disable WAF
```yaml
infrastructure:
  nodes:
    - name: nginx-proxy
      waf_mode: "detection"  # off/detection/prevention
```

---

**💡 Tip**: Start with `test_all_features` to validate system functionality before using other scenarios.
