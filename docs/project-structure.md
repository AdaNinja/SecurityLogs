# Project Structure

This document provides a detailed overview of the SecurityLogs project structure and organization.

## Directory Overview

```
SecurityLogs/
├── README.md                    # Project overview and quick start
├── Makefile                     # Unified project management
├── .env                         # Environment variables
├── containers/                  # Docker container definitions
│   ├── webapp/                 # Vulnerable web application
│   ├── attacker/               # Attack execution container
│   └── tcpdump/               # Network traffic capture
├── control/                    # Control center and automation
│   ├── network/               # Network emulation tools
│   ├── automation/            # Experiment automation scripts
│   └── README.md              # Control center documentation
├── scenarios/                  # Attack scenarios
│   └── low-and-slow-sqli/     # SQL injection attack scenario
├── data/                       # Generated data and logs
│   ├── logs/                  # Application and container logs
│   ├── pcap/                  # Network traffic captures
│   └── output/                # Analysis results and reports
├── docs/                       # Project documentation
│   ├── setup.md               # Installation and setup guide
│   ├── usage.md               # Usage instructions
│   ├── troubleshooting.md     # Troubleshooting guide
│   └── project-structure.md   # This file
└── .git/                       # Version control
```

## Detailed Structure

### Root Level Files

- **`README.md`**: Project overview, quick start guide, and basic usage instructions
- **`Makefile`**: Unified management for all scenarios, containers, and automation
- **`.env`**: Environment variables for the project

### Containers Directory

The `containers/` directory contains Docker container definitions for all components:

```
containers/
├── webapp/                     # Vulnerable web application
│   ├── Dockerfile             # Container build instructions
│   ├── config/                # Configuration files
│   ├── scripts/               # Container scripts
│   └── webapp/                # Web application files
├── attacker/                   # Attack execution container
│   ├── Dockerfile             # Container build instructions
│   ├── config/                # Configuration files
│   └── scripts/               # Attack scripts
└── tcpdump/                   # Network traffic capture
    ├── Dockerfile             # Container build instructions
    └── scripts/               # Capture scripts
```

### Control Directory

The `control/` directory contains centralized tools for experiment management:

```
control/
├── README.md                  # Control center documentation
├── network/                   # Network emulation tools
│   ├── apply_netem.sh        # Apply network conditions
│   ├── reset_netem.sh        # Reset network conditions
│   └── netem_profiles/       # Network condition configurations
└── automation/                # Experiment automation scripts
    ├── run_all_variants.sh   # Execute all attack variants
    ├── capture.sh            # Complete capture workflow
    └── multi_source_logger.py # Multi-source log analysis
```

### Scenarios Directory

The `scenarios/` directory contains individual attack scenarios:

```
scenarios/
└── low-and-slow-sqli/         # SQL injection attack scenario
    ├── README.md              # Scenario documentation (integrated)
    ├── docker-compose.yml     # Container orchestration
    ├── config/                # Scenario configuration
    │   ├── scenario.env       # Main scenario configuration
    │   └── variants.yml       # Attack variant definitions
    ├── scripts/               # Scenario-specific scripts
    │   ├── attack_modules/    # Attack script modules
    │   ├── benign_modules/    # Benign traffic modules
    │   ├── interleaved_attack.sh # Interleaved attack script
    │   └── config_loader.py   # Configuration loader
    └── requirements.txt       # Python dependencies
```

### Data Directory

The `data/` directory contains all generated data and logs:

```
data/
├── logs/                      # Application and container logs
│   └── nginx/                # Nginx log files
├── pcap/                      # Network traffic captures
└── output/                    # Analysis results and reports
    └── variants/              # Per-variant attack results
```

### Documentation Directory

The `docs/` directory contains comprehensive project documentation:

```
docs/
├── setup.md                   # Installation and setup guide
├── usage.md                   # Usage instructions and examples
├── troubleshooting.md         # Troubleshooting guide
└── project-structure.md       # This file
```

## File Organization Principles

### 1. Separation of Concerns
- **Containers**: Isolated Docker environments for each component
- **Control**: Centralized automation and network management
- **Scenarios**: Individual attack scenarios with specific configurations
- **Data**: Centralized data storage and organization
- **Documentation**: Comprehensive guides and references

### 2. Modularity
- Each container is self-contained with its own configuration
- Scripts are organized by function (network, automation, attack, benign)
- Configuration files are separated from implementation
- Documentation is organized by purpose (setup, usage, troubleshooting)

### 3. Scalability
- Easy to add new scenarios by following the existing structure
- Control scripts can be extended for new automation needs
- Container definitions can be reused across scenarios
- Documentation structure supports new content types

### 4. Maintainability
- Clear separation between project-level and scenario-level files
- Consistent naming conventions throughout
- Centralized control through Makefile
- Comprehensive documentation for all components

## Key Files and Their Purposes

### Project Management
- **`Makefile`**: Unified interface for all project operations
- **`README.md`**: Quick start and project overview
- **`.env`**: Environment variables and configuration

### Container Management
- **`containers/*/Dockerfile`**: Container build instructions
- **`scenarios/*/docker-compose.yml`**: Container orchestration
- **`containers/*/config/`**: Container-specific configurations

### Automation and Control
- **`control/network/`**: Network emulation and traffic control
- **`control/automation/`**: Experiment automation and data collection
- **`control/README.md`**: Control center documentation

### Scenario Configuration
- **`scenarios/*/config/scenario.env`**: Main scenario configuration
- **`scenarios/*/config/variants.yml`**: Attack variant definitions
- **`scenarios/*/scripts/`**: Scenario-specific automation scripts

### Data Management
- **`data/logs/`**: Application and system logs
- **`data/pcap/`**: Network traffic captures
- **`data/output/`**: Analysis results and reports

### Documentation
- **`docs/setup.md`**: Installation and configuration guide
- **`docs/usage.md`**: Usage instructions and examples
- **`docs/troubleshooting.md`**: Problem-solving guide
- **`scenarios/*/README.md`**: Scenario-specific documentation

## Naming Conventions

### Directories
- Use lowercase with hyphens for multi-word directories
- Examples: `low-and-slow-sqli`, `attack_modules`, `benign_modules`

### Files
- Use lowercase with underscores for multi-word files
- Examples: `docker_compose.yml`, `multi_source_logger.py`, `apply_netem.sh`

### Containers
- Use `securitylogs-` prefix for all containers
- Examples: `securitylogs-webapp`, `securitylogs-attacker`, `securitylogs-tcpdump`

### Scripts
- Use descriptive names that indicate function
- Examples: `run_all_variants.sh`, `apply_netem.sh`, `multi_source_logger.py`

## Version Control

### Git Structure
- **`.git/`**: Version control metadata
- **`.gitignore`**: Exclude patterns for version control
- **`README.md`**: Project documentation in version control

### Ignored Files
- **`data/`**: Generated data (not version controlled)
- **`*.log`**: Log files
- **`*.pcap`**: PCAP files
- **`__pycache__/`**: Python cache files
- **`.env.local`**: Local environment overrides

## Best Practices

### 1. File Organization
- Keep related files together in logical directories
- Use consistent naming conventions
- Separate configuration from implementation
- Organize documentation by purpose

### 2. Container Design
- Each container has a single, well-defined purpose
- Containers are self-contained with minimal dependencies
- Configuration is externalized where possible
- Health checks are implemented for critical containers

### 3. Script Organization
- Scripts are organized by function (network, automation, attack)
- Common functionality is centralized
- Scripts are parameterized for flexibility
- Error handling and logging are implemented

### 4. Documentation
- Documentation is comprehensive and up-to-date
- Examples are provided for common use cases
- Troubleshooting guides are included
- Structure is logical and easy to navigate

## Extending the Project

### Adding New Scenarios
1. Create new directory in `scenarios/`
2. Follow existing structure and naming conventions
3. Add scenario-specific configuration files
4. Update main `README.md` with new scenario
5. Add scenario-specific Makefile targets

### Adding New Containers
1. Create new directory in `containers/`
2. Implement Dockerfile and configuration
3. Update docker-compose.yml files
4. Add container-specific Makefile targets
5. Update documentation

### Adding New Automation
1. Add scripts to appropriate `control/` subdirectory
2. Update `control/README.md` with new functionality
3. Add corresponding Makefile targets
4. Update documentation

### Adding New Documentation
1. Add files to appropriate `docs/` subdirectory
2. Follow existing documentation structure
3. Update main `README.md` with references
4. Maintain consistency with existing documentation style 