# Complexity Configuration System

## Overview

The complexity configuration system allows you to customize how attack scenario variants are scored and analyzed. This system provides both predefined presets and fully customizable configurations to meet specific testing requirements.

## Academic Research Basis

The weight distribution in this system is based on several authoritative academic studies:

### Key Research References:
1. **MITRE ATT&CK Framework (2018)** - Attack technique complexity assessment
2. **Garcia-Teodoro et al. (2009)** - IDS evaluation metrics and environmental factors
3. **Sommer & Paxson (2010)** - Machine learning for network intrusion detection
4. **Laskov et al. (2004)** - Supervised vs unsupervised learning in intrusion detection

For detailed academic research basis, see [ACADEMIC_RESEARCH_BASIS.md](ACADEMIC_RESEARCH_BASIS.md).

## Predefined Complexity Presets

### 1. Basic Difficulty
- **Target**: Beginners and basic detection system testing
- **Max Score**: 3.0
- **Weight Distribution**:
  - Background Activity: 40%
  - Attack Stealth: 30%
  - Evasion Techniques: 20%
  - Noise Level: 10%

### 2. Intermediate Difficulty
- **Target**: Intermediate detection systems and security analysts
- **Max Score**: 4.0
- **Weight Distribution**:
  - Background Activity: 35%
  - Attack Stealth: 35%
  - Evasion Techniques: 25%
  - Noise Level: 5%

### 3. Advanced Difficulty
- **Target**: Advanced detection systems and threat hunters
- **Max Score**: 5.0
- **Weight Distribution**:
  - Background Activity: 30%
  - Attack Stealth: 40%
  - Evasion Techniques: 30%
  - Noise Level: 0%

## Configuration Methods

### Method 1: Using Presets
```yaml
variants:
  simple:
    name: "Simple Variant"
    complexity: "basic"  # Uses basic preset
    # ... other configuration
```

### Method 2: Preset with Overrides
```yaml
variants:
  custom_basic:
    name: "Custom Basic Variant"
    complexity: "basic"
    complexity_config:
      preset: "basic"
      background_activity_weight: 0.45  # Override specific parameter
      max_score: 3.5                   # Override max score
```

### Method 3: Fully Custom Configuration
```yaml
variants:
  fully_custom:
    name: "Fully Custom Variant"
    complexity: "custom"
    complexity_config:
      name: "Custom Difficulty"
      description: "Custom complexity configuration"
      background_activity_weight: 0.4
      attack_stealth_weight: 0.35
      evasion_technique_weight: 0.2
      noise_level_weight: 0.05
      max_score: 4.5
```

## Complexity Factors

### 1. Background Activity Weight (0.2-0.5)
- **Higher values**: More emphasis on background activities
- **Impact**: Affects detection difficulty in busy environments
- **Calculation**: Number of background activities × 0.5
- **Considerations**: 
  - Office work, multimedia, communication tools
  - Number and types of activities

### 2. Attack Stealth Weight (0.15-0.5)
- **Higher values**: More emphasis on stealth characteristics
- **Impact**: Affects how well attacks can hide from detection
- **Calculation**: Stealth level (low=1, medium=2, high=3)
- **Considerations**:
  - Stealth level (low/medium/high)
  - Attack timing patterns
  - Command complexity

### 3. Evasion Technique Weight (0.05-0.3)
- **Higher values**: More emphasis on evasion capabilities
- **Impact**: Affects ability to bypass detection mechanisms
- **Calculation**: Number of evasion techniques × 1
- **Considerations**:
  - Number and sophistication of evasion techniques
  - Anti-detection measures
  - Obfuscation methods

### 4. Noise Level Weight (0.0-0.3)
- **Higher values**: More emphasis on environmental noise
- **Impact**: Affects signal-to-noise ratio for detection
- **Calculation**: (Number of activities × Average intensity) / 2.0
- **Intensity Mapping**: minimal=1, moderate=2, high=3
- **Example**: 4 activities with avg intensity 2.5 = (4 × 2.5) / 2.0 = 5.0 points
- **Purpose**: Represents environmental noise level that affects detection

## Scoring Algorithm

The complexity score is calculated using the following formula:

```
Score = (Background_Score × Background_Weight) +
        (Stealth_Score × Stealth_Weight) +
        (Evasion_Score × Evasion_Weight) +
        (Noise_Score × Noise_Weight)
```

Where each component score is calculated based on:

### Background Score
- **Formula**: Number of background activities × 0.5
- **Example**: 4 activities = 4 × 0.5 = 2.0 points

### Stealth Score  
- **Formula**: Stealth level mapping (low=1, medium=2, high=3)
- **Example**: High stealth = 3 points

### Evasion Score
- **Formula**: Number of evasion techniques × 1
- **Example**: 3 evasion techniques = 3 × 1 = 3 points

### Noise Score
- **Formula**: (Number of activities × Average intensity) / 2.0
- **Example**: 4 activities with avg intensity 2.5 = (4 × 2.5) / 2.0 = 5.0 points

## Best Practices

### 1. Weight Balancing
- Ensure weights sum to approximately 1.0 for balanced scoring
- Consider the specific testing objectives when adjusting weights
- Use presets as starting points and customize as needed

### 2. Max Score Setting
- Basic: 2.5-3.5
- Intermediate: 3.5-4.5
- Advanced: 4.5-5.0
- Custom: Based on specific requirements

### 3. Testing Scenarios
- **Detection Testing**: Focus on stealth and evasion weights
- **Noise Testing**: Focus on background activity and noise weights
- **Comprehensive Testing**: Use balanced weights

### 4. Validation
- Test configurations with known scenarios
- Validate that scores align with expected complexity levels
- Adjust weights based on detection system performance

## Example Configurations

### Stealth-Focused Testing
```yaml
complexity_config:
  preset: "advanced"
  attack_stealth_weight: 0.5
  evasion_technique_weight: 0.3
  background_activity_weight: 0.2
  noise_level_weight: 0.0
```

### Noise-Focused Testing
```yaml
complexity_config:
  preset: "intermediate"
  background_activity_weight: 0.5
  noise_level_weight: 0.3
  attack_stealth_weight: 0.15
  evasion_technique_weight: 0.05
```

### Balanced Testing
```yaml
complexity_config:
  background_activity_weight: 0.35
  attack_stealth_weight: 0.35
  evasion_technique_weight: 0.25
  noise_level_weight: 0.05
```

## Integration with Detection Analysis

The complexity configuration system integrates with the detection analysis to provide:

1. **Normalized Scoring**: Scores are normalized against max_score for consistent comparison
2. **Predicted Metrics**: Complexity scores influence predicted detection metrics
3. **Comparative Analysis**: Enables comparison across different complexity configurations
4. **Custom Reporting**: Detailed reports include complexity configuration information

This system provides the flexibility needed for comprehensive security testing while maintaining consistency and reproducibility across different scenarios and testing environments. 