#!/bin/bash
#
# CyberRange Unified Cleanup Script
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${CYAN}=== $1 ===${NC}"
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
    echo "CyberRange Unified Cleanup Script"
    echo "Usage: $0 [OPTIONS] [EXPERIMENT_NAME]"
    echo ""
    echo "Cleanup Types:"
    echo "  -e, --experiment [NAME]  Clean specific experiment data"
    echo "  -a, --all-experiments    Clean all experiment data"
    echo "  -d, --docker             Clean Docker resources (containers, images, networks)"
    echo "  -l, --logs               Clean logs directory only"
    echo "  -o, --output             Clean output directory only"
    echo "  -s, --shared             Clean shared_data only"
    echo "  -x, --exfiltrated        Clean exfiltrated_data only"
    echo "  --full                   Full cleanup (everything)"
    echo ""
    echo "Options:"
    echo "  -f, --force              Force cleanup without confirmation"
    echo "  -q, --quiet              Quiet mode (less output)"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --experiment test-all-features_20250830_222834"
    echo "  $0 --all-experiments"
    echo "  $0 --docker"
    echo "  $0 --full --force"
    echo ""
}

check_sudo() {
    if ! sudo -n true 2>/dev/null; then
        print_warning "Some operations may need sudo privileges for Docker-created files."
        print_info "You may be prompted for your password if needed."
        echo ""
    fi
}

safe_remove() {
    local path="$1"
    local description="$2"
    local quiet="$3"
    
    if [ ! -e "$path" ]; then
        [ "$quiet" != "true" ] && print_warning "$description not found: $path"
        return 0
    fi
    
    if [[ "$path" != *"/shared_data/"* ]] && [[ "$path" != *"/exfiltrated_data/"* ]] && 
       [[ "$path" != *"/logs/"* ]] && [[ "$path" != *"/output/"* ]] &&
       [[ "$path" != "logs" ]] && [[ "$path" != "output" ]] &&
       [[ "$path" != "logs/*" ]] && [[ "$path" != "output/*" ]]; then
        print_error "Unsafe path detected: $path"
        return 1
    fi
    
    if rm -rf "$path" 2>/dev/null; then
        [ "$quiet" != "true" ] && print_success "Removed $description: $path"
        return 0
    fi
    
    # sudo required
    [ "$quiet" != "true" ] && print_warning "Need sudo to remove $description: $path"
    if sudo rm -rf "$path" 2>/dev/null; then
        [ "$quiet" != "true" ] && print_success "Removed $description (with sudo): $path"
        return 0
    else
        print_error "Failed to remove $description: $path"
        return 1
    fi
}

# clean Docker resources
cleanup_docker() {
    local force="$1"
    local quiet="$2"
    
    print_header "Docker Cleanup"
    
    if ! command -v docker &> /dev/null; then
        print_warning "Docker not found, skipping Docker cleanup"
        return 0
    fi
    
    # show current status
    if [ "$quiet" != "true" ]; then
        echo "Current containers:"
        docker ps -a --filter "name=juice-shop" --filter "name=nginx" --filter "name=attacker" --filter "name=benign_user" --format "table {{.Names}}\t{{.Status}}\t{{.Image}}" 2>/dev/null || echo "  No CyberRange containers found"
        echo ""
    fi
    
    # confirm operation
    if [ "$force" != "true" ]; then
        read -p "Clean Docker containers, networks, and unused resources? (y/N): " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_warning "Docker cleanup cancelled"
            return 0
        fi
    fi
    
    # stop and delete CyberRange containers
    [ "$quiet" != "true" ] && print_info "Stopping CyberRange containers..."
    docker ps -q --filter "name=juice-shop" --filter "name=nginx" --filter "name=attacker" --filter "name=benign_user" | xargs -r docker stop 2>/dev/null || true
    
    [ "$quiet" != "true" ] && print_info "Removing CyberRange containers..."
    docker ps -aq --filter "name=juice-shop" --filter "name=nginx" --filter "name=attacker" --filter "name=benign_user" | xargs -r docker rm 2>/dev/null || true
    
    # clean networks
    [ "$quiet" != "true" ] && print_info "Cleaning CyberRange networks..."
    docker network ls --filter "name=internal-net" --filter "name=external-net" -q | xargs -r docker network rm 2>/dev/null || true
    
    # clean unused resources
    [ "$quiet" != "true" ] && print_info "Cleaning unused Docker resources..."
    docker image prune -f >/dev/null 2>&1 || true
    docker volume prune -f >/dev/null 2>&1 || true
    docker network prune -f >/dev/null 2>&1 || true
    
    print_success "Docker cleanup completed"
}

# clean experiment data
cleanup_experiment_data() {
    local exp_name="$1"
    local quiet="$2"
    
    if [ -z "$exp_name" ]; then
        print_error "Experiment name required"
        return 1
    fi
    
    print_header "Cleaning Experiment: $exp_name"
    
    local cleaned=false
    
    # clean various data directories
    for base_dir in "shared_data" "exfiltrated_data" "logs" "output"; do
        for pattern in "$base_dir/$exp_name" "$base_dir/${exp_name}_*"; do
            for dir in $pattern; do
                if [ -d "$dir" ]; then
                    safe_remove "$dir" "$base_dir data" "$quiet"
                    cleaned=true
                fi
            done
        done
    done
    
    if [ "$cleaned" = "true" ]; then
        print_success "Cleanup completed for: $exp_name"
    else
        print_warning "No data found for experiment: $exp_name"
    fi
}

# clean all experiment data
cleanup_all_experiments() {
    local force="$1"
    local quiet="$2"
    
    print_header "Cleaning All Experiment Data"
    
    # collect all experiments
    local experiments=()
    for base_dir in "shared_data" "exfiltrated_data" "logs" "output"; do
        if [ -d "$base_dir" ]; then
            for dir in "$base_dir"/*/; do
                if [ -d "$dir" ]; then
                    experiments+=($(basename "$dir"))
                fi
            done
        fi
    done
    
    # remove duplicates
    local unique_experiments=($(printf '%s\n' "${experiments[@]}" | sort -u))
    
    if [ ${#unique_experiments[@]} -eq 0 ]; then
        print_warning "No experiment data found"
        return 0
    fi
    
    if [ "$quiet" != "true" ]; then
        print_warning "Found ${#unique_experiments[@]} experiments to clean:"
        for exp in "${unique_experiments[@]}"; do
            echo "  - $exp"
        done
        echo ""
    fi
    
    # confirm operation
    if [ "$force" != "true" ]; then
        read -p "Clean all experiment data? (y/N): " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_warning "Cleanup cancelled"
            return 0
        fi
    fi
    
    # batch clean
    for base_dir in "shared_data" "exfiltrated_data" "logs" "output"; do
        if [ -d "$base_dir" ]; then
            safe_remove "$base_dir/*" "$base_dir" "$quiet"
        fi
    done
    
    print_success "All experiment data cleaned"
}

# clean specific directory
cleanup_directory() {
    local dir_name="$1"
    local force="$2"
    local quiet="$3"
    
    print_header "Cleaning $dir_name Directory"
    
    if [ ! -d "$dir_name" ]; then
        print_warning "$dir_name directory not found"
        return 0
    fi
    
    # confirm operation
    if [ "$force" != "true" ]; then
        read -p "Clean $dir_name directory? (y/N): " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_warning "$dir_name cleanup cancelled"
            return 0
        fi
    fi
    
    safe_remove "$dir_name/*" "$dir_name contents" "$quiet"
    
    # clean related files in root directory
    if [ "$dir_name" = "logs" ]; then
        rm -f *.log *.csv *.pcap 2>/dev/null || true
        [ "$quiet" != "true" ] && print_success "Root directory log files cleaned"
    fi
    
    print_success "$dir_name directory cleaned"
}

# full cleanup
full_cleanup() {
    local force="$1"
    local quiet="$2"
    
    print_header "Full CyberRange Cleanup"
    
    if [ "$force" != "true" ]; then
        print_warning "This will clean ALL experiment data, logs, output, and Docker resources!"
        read -p "Are you sure? (y/N): " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_warning "Full cleanup cancelled"
            return 0
        fi
    fi
    
    cleanup_docker "true" "$quiet"
    cleanup_all_experiments "true" "$quiet"
    
    print_success "Full cleanup completed!"
}

# list current status
list_status() {
    print_header "CyberRange Status"
    
    echo "📁 Data Directories:"
    for dir in "shared_data" "exfiltrated_data" "logs" "output"; do
        if [ -d "$dir" ]; then
            count=$(find "$dir" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
            size=$(du -sh "$dir" 2>/dev/null | cut -f1)
            echo "  $dir: $count experiments ($size)"
        else
            echo "  $dir: not found"
        fi
    done
    
    echo ""
    echo "🐳 Docker Status:"
    if command -v docker &> /dev/null; then
        containers=$(docker ps -a --filter "name=juice-shop" --filter "name=nginx" --filter "name=attacker" --filter "name=benign_user" -q | wc -l)
        networks=$(docker network ls --filter "name=internal-net" --filter "name=external-net" -q | wc -l)
        echo "  Containers: $containers"
        echo "  Networks: $networks"
    else
        echo "  Docker not available"
    fi
}

# main function
main() {
    local experiment_name=""
    local cleanup_type=""
    local force_flag=false
    local quiet_flag=false
    
    # parse parameters
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--experiment)
                cleanup_type="experiment"
                experiment_name="$2"
                shift 2
                ;;
            -a|--all-experiments)
                cleanup_type="all_experiments"
                shift
                ;;
            -d|--docker)
                cleanup_type="docker"
                shift
                ;;
            -l|--logs)
                cleanup_type="logs"
                shift
                ;;
            -o|--output)
                cleanup_type="output"
                shift
                ;;
            -s|--shared)
                cleanup_type="shared"
                shift
                ;;
            -x|--exfiltrated)
                cleanup_type="exfiltrated"
                shift
                ;;
            --full)
                cleanup_type="full"
                shift
                ;;
            -f|--force)
                force_flag=true
                shift
                ;;
            -q|--quiet)
                quiet_flag=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                if [ -z "$cleanup_type" ]; then
                    cleanup_type="experiment"
                    experiment_name="$1"
                fi
                shift
                ;;
        esac
    done
    
    # if no operation is specified, show status
    if [ -z "$cleanup_type" ]; then
        list_status
        echo ""
        print_info "Use --help for usage information"
        exit 0
    fi
    
    # check sudo permissions
    check_sudo
    
    # execute corresponding cleanup operations
    case $cleanup_type in
        "experiment")
            if [ -z "$experiment_name" ]; then
                print_error "Experiment name required for --experiment"
                exit 1
            fi
            cleanup_experiment_data "$experiment_name" "$quiet_flag"
            ;;
        "all_experiments")
            cleanup_all_experiments "$force_flag" "$quiet_flag"
            ;;
        "docker")
            cleanup_docker "$force_flag" "$quiet_flag"
            ;;
        "logs")
            cleanup_directory "logs" "$force_flag" "$quiet_flag"
            ;;
        "output")
            cleanup_directory "output" "$force_flag" "$quiet_flag"
            ;;
        "shared")
            cleanup_directory "shared_data" "$force_flag" "$quiet_flag"
            ;;
        "exfiltrated")
            cleanup_directory "exfiltrated_data" "$force_flag" "$quiet_flag"
            ;;
        "full")
            full_cleanup "$force_flag" "$quiet_flag"
            ;;
        *)
            print_error "Unknown cleanup type: $cleanup_type"
            exit 1
            ;;
    esac
    
    echo ""
    print_success "Cleanup operation completed!"
    print_info "Run './scripts/cleanup.sh' to see current status"
}

# run main function
main "$@"
