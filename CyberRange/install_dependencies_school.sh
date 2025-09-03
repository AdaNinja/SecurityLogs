#!/bin/bash
#
# CyberRange School Environment Installation Script
# Handles externally-managed-environment restrictions
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
    echo "CyberRange School Environment Installation Script"
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -m, --minimal     Install minimal dependencies only"
    echo "  -f, --full        Install full dependencies (default)"
    echo "  -u, --user        Install to user directory (--user flag)"
    echo "  -s, --system      Force system installation (--break-system-packages)"
    echo "  -v, --verbose     Verbose output"
    echo "  -h, --help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                # Try virtual env, fallback to user install"
    echo "  $0 --user         # Install to user directory"
    echo "  $0 --system       # Force system installation (risky)"
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
        return 0
    else
        print_warning "No virtual environment detected."
        return 1
    fi
}

try_virtual_env() {
    print_header "Attempting Virtual Environment Creation"
    
    # Check if python3-venv is available
    if python3 -c "import venv" 2>/dev/null; then
        print_success "python3-venv is available"
        
        # Create virtual environment
        if python3 -m venv cyberrange_env; then
            print_success "Virtual environment created: cyberrange_env"
            
            # Activate virtual environment
            source cyberrange_env/bin/activate
            print_success "Virtual environment activated"
            
            return 0
        else
            print_error "Failed to create virtual environment"
            return 1
        fi
    else
        print_warning "python3-venv not available. Trying alternative methods..."
        return 1
    fi
}

install_dependencies() {
    local requirements_file="$1"
    local install_method="$2"
    local verbose_flag="$3"
    
    print_header "Installing Python Dependencies"
    
    if [ ! -f "$requirements_file" ]; then
        print_error "Requirements file not found: $requirements_file"
        exit 1
    fi
    
    print_info "Using requirements file: $requirements_file"
    print_info "Install method: $install_method"
    
    # Build pip install command
    local pip_cmd="pip3 install"
    
    if [ "$verbose_flag" = "true" ]; then
        pip_cmd="$pip_cmd --verbose"
    fi
    
    case $install_method in
        "user")
            pip_cmd="$pip_cmd --user"
            ;;
        "system")
            pip_cmd="$pip_cmd --break-system-packages"
            print_warning "Using --break-system-packages (risky)"
            ;;
        "venv")
            # Already in virtual environment
            ;;
    esac
    
    pip_cmd="$pip_cmd -r $requirements_file"
    
    print_info "Running: $pip_cmd"
    
    # Install dependencies
    if eval "$pip_cmd"; then
        print_success "Dependencies installed successfully"
        return 0
    else
        print_error "Failed to install dependencies with method: $install_method"
        return 1
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
        return 0
    else
        print_error "Dependency verification failed"
        return 1
    fi
}

show_usage_instructions() {
    print_header "Usage Instructions"
    
    if [ -d "cyberrange_env" ]; then
        print_info "Virtual environment created. To use it:"
        echo "  source cyberrange_env/bin/activate"
        echo "  python3 run_scenario.py --config scenarios/test_multi_nodes.yaml"
        echo "  deactivate  # when done"
    else
        print_info "Dependencies installed to user directory. You can now run:"
        echo "  python3 run_scenario.py --config scenarios/test_multi_nodes.yaml"
    fi
}

main() {
    local requirements_file="requirements.txt"
    local install_method="auto"
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
            -u|--user)
                install_method="user"
                shift
                ;;
            -s|--system)
                install_method="system"
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
    
    # Check if already in virtual environment
    if check_python; then
        print_info "Already in virtual environment, proceeding with installation"
        install_method="venv"
    else
        # Try different installation methods
        if [ "$install_method" = "auto" ]; then
            print_info "Trying automatic installation method selection..."
            
            # Try virtual environment first
            if try_virtual_env; then
                install_method="venv"
            else
                # Fallback to user installation
                print_info "Virtual environment failed, trying user installation..."
                install_method="user"
            fi
        fi
    fi
    
    # Install dependencies
    if install_dependencies "$requirements_file" "$install_method" "$verbose_flag"; then
        verify_installation
        show_usage_instructions
        print_success "CyberRange dependencies installation completed!"
    else
        print_error "Installation failed. Try:"
        echo "  $0 --user     # Install to user directory"
        echo "  $0 --system   # Force system installation (risky)"
        exit 1
    fi
}

# Run main function
main "$@"
