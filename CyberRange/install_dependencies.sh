#!/bin/bash
#
# CyberRange Dependency Installation Script
# Installs Python dependencies for the CyberRange system
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

show_help() {
    echo "CyberRange Dependency Installation Script"
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -m, --minimal     Install minimal dependencies only"
    echo "  -f, --full        Install full dependencies (default)"
    echo "  -u, --upgrade     Upgrade existing packages"
    echo "  -v, --verbose     Verbose output"
    echo "  -h, --help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                # Install full dependencies"
    echo "  $0 --minimal      # Install minimal dependencies"
    echo "  $0 --upgrade      # Upgrade existing packages"
    echo ""
}

check_python() {
    print_header "Checking Python Environment"
    
    # Check Python version
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
        print_success "Python 3 found: $PYTHON_VERSION"
    else
        print_error "Python 3 not found. Please install Python 3.8 or higher."
        exit 1
    fi
    
    # Check pip
    if command -v pip3 &> /dev/null; then
        PIP_VERSION=$(pip3 --version 2>&1 | cut -d' ' -f2)
        print_success "pip3 found: $PIP_VERSION"
    else
        print_error "pip3 not found. Please install pip3."
        exit 1
    fi
    
    # Check if we're in a virtual environment
    if [[ "$VIRTUAL_ENV" != "" ]]; then
        print_success "Virtual environment detected: $VIRTUAL_ENV"
    else
        print_warning "No virtual environment detected. Consider using venv or conda."
        print_info "You can create a virtual environment with: python3 -m venv venv"
    fi
}

check_docker() {
    print_header "Checking Docker Environment"
    
    if command -v docker &> /dev/null; then
        DOCKER_VERSION=$(docker --version 2>&1 | cut -d' ' -f3 | cut -d',' -f1)
        print_success "Docker found: $DOCKER_VERSION"
        
        # Check if Docker daemon is running
        if docker info &> /dev/null; then
            print_success "Docker daemon is running"
        else
            print_warning "Docker daemon is not running. You may need to start it."
        fi
    else
        print_warning "Docker not found. Please install Docker for container orchestration."
    fi
    
    if command -v docker-compose &> /dev/null; then
        COMPOSE_VERSION=$(docker-compose --version 2>&1 | cut -d' ' -f3 | cut -d',' -f1)
        print_success "Docker Compose found: $COMPOSE_VERSION"
    else
        print_warning "Docker Compose not found. Please install Docker Compose."
    fi
}

install_dependencies() {
    local requirements_file="$1"
    local upgrade_flag="$2"
    local verbose_flag="$3"
    
    print_header "Installing Python Dependencies"
    
    if [ ! -f "$requirements_file" ]; then
        print_error "Requirements file not found: $requirements_file"
        exit 1
    fi
    
    print_info "Using requirements file: $requirements_file"
    
    # Build pip install command
    local pip_cmd="pip3 install"
    
    if [ "$upgrade_flag" = "true" ]; then
        pip_cmd="$pip_cmd --upgrade"
    fi
    
    if [ "$verbose_flag" = "true" ]; then
        pip_cmd="$pip_cmd --verbose"
    fi
    
    pip_cmd="$pip_cmd -r $requirements_file"
    
    print_info "Running: $pip_cmd"
    
    # Install dependencies
    if eval "$pip_cmd"; then
        print_success "Dependencies installed successfully"
    else
        print_error "Failed to install dependencies"
        exit 1
    fi
}

verify_installation() {
    print_header "Verifying Installation"
    
    # Test critical imports
    local test_script="
import sys
try:
    import docker
    print('✅ docker module imported successfully')
except ImportError as e:
    print(f'❌ docker module import failed: {e}')
    sys.exit(1)

try:
    import yaml
    print('✅ yaml module imported successfully')
except ImportError as e:
    print(f'❌ yaml module import failed: {e}')
    sys.exit(1)

try:
    import pandas
    print('✅ pandas module imported successfully')
except ImportError as e:
    print(f'❌ pandas module import failed: {e}')
    sys.exit(1)

try:
    import requests
    print('✅ requests module imported successfully')
except ImportError as e:
    print(f'❌ requests module import failed: {e}')
    sys.exit(1)

try:
    from jsonpath_ng import parse
    print('✅ jsonpath-ng module imported successfully')
except ImportError as e:
    print(f'❌ jsonpath-ng module import failed: {e}')
    sys.exit(1)

print('✅ All critical modules imported successfully')
"
    
    if python3 -c "$test_script"; then
        print_success "All dependencies verified successfully"
    else
        print_error "Dependency verification failed"
        exit 1
    fi
}

main() {
    local requirements_file="requirements.txt"
    local upgrade_flag=false
    local verbose_flag=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -m|--minimal)
                requirements_file="requirements-minimal.txt"
                shift
                ;;
            -f|--full)
                requirements_file="requirements.txt"
                shift
                ;;
            -u|--upgrade)
                upgrade_flag=true
                shift
                ;;
            -v|--verbose)
                verbose_flag=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Run installation process
    check_python
    check_docker
    install_dependencies "$requirements_file" "$upgrade_flag" "$verbose_flag"
    verify_installation
    
    echo ""
    print_success "CyberRange dependencies installation completed!"
    print_info "You can now run scenarios with: python3 run_scenario.py --config scenarios/test_multi_nodes.yaml"
}

# Run main function
main "$@"
