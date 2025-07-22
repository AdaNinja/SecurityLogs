#!/bin/bash

# Pcap Converter Script
# Converts pcap files to various readable formats
# Usage: ./pcap_converter.sh [options] [pcap_file]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
PCAP_FILE=""
OUTPUT_DIR=""
FORMAT="all"
LATEST_ONLY=false

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check dependencies
check_dependencies() {
    local missing_deps=()
    
    if ! command -v tcpdump &> /dev/null; then
        missing_deps+=("tcpdump")
    fi
    
    if ! command -v jq &> /dev/null; then
        missing_deps+=("jq")
    fi
    
    if ! command -v tshark &> /dev/null; then
        print_warning "tshark not found - detailed analysis will be limited"
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        print_status "Installing missing dependencies..."
        sudo apt-get update
        sudo apt-get install -y "${missing_deps[@]}"
    fi
}

# Function to find latest moderate experiment
find_latest_moderate() {
    local base_dir="./data/output/single_variant"
    if [ ! -d "$base_dir" ]; then
        print_error "Base directory $base_dir not found"
        exit 1
    fi
    
    local latest_dir=$(find "$base_dir" -name "moderate_*" -type d | sort | tail -1)
    if [ -z "$latest_dir" ]; then
        print_error "No moderate experiment directories found"
        exit 1
    fi
    
    echo "$latest_dir"
}

# Function to find pcap file in directory
find_pcap_file() {
    local dir="$1"
    local pcap_file=$(find "$dir" -name "*.pcap" -type f | head -1)
    
    if [ -z "$pcap_file" ]; then
        print_error "No pcap file found in $dir"
        exit 1
    fi
    
    echo "$pcap_file"
}

# Function to generate summary
generate_summary() {
    local pcap_file="$1"
    local output_file="$2"
    
    print_status "Generating packet summary..."
    tcpdump -r "$pcap_file" -n -tttt | head -100 > "$output_file"
    echo "..." >> "$output_file"
    echo "Total packets: $(tcpdump -r "$pcap_file" -n | wc -l)" >> "$output_file"
}

# Function to extract HTTP content
extract_http_content() {
    local pcap_file="$1"
    local output_file="$2"
    
    print_status "Extracting HTTP content..."
    
    # Extract HTTP requests and responses
    tcpdump -r "$pcap_file" -A -s 0 'tcp port 80 or tcp port 443' 2>/dev/null | \
        grep -E "(GET|POST|HTTP/|Host:|User-Agent:|Content-Length:)" > "$output_file" || true
    
    if [ ! -s "$output_file" ]; then
        echo "No HTTP content found" > "$output_file"
    fi
}

# Function to generate detailed analysis
generate_detailed_analysis() {
    local pcap_file="$1"
    local output_file="$2"
    
    print_status "Generating detailed analysis..."
    
    {
        echo "=== PCAP FILE ANALYSIS ==="
        echo "File: $pcap_file"
        echo "Size: $(du -h "$pcap_file" | cut -f1)"
        echo "Created: $(stat -c %y "$pcap_file")"
        echo ""
        
        echo "=== PACKET STATISTICS ==="
        tcpdump -r "$pcap_file" -n | wc -l | xargs echo "Total packets:"
        echo ""
        
        echo "=== PROTOCOL BREAKDOWN ==="
        tcpdump -r "$pcap_file" -n | grep -o "proto [A-Z]*" | sort | uniq -c | sort -nr || echo "No protocol information available"
        echo ""
        
        echo "=== PORT ANALYSIS ==="
        tcpdump -r "$pcap_file" -n | grep -o ":[0-9]*" | sort | uniq -c | sort -nr | head -10 || echo "No port information available"
        echo ""
        
        echo "=== IP ADDRESSES ==="
        tcpdump -r "$pcap_file" -n | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort | uniq -c | sort -nr | head -10 || echo "No IP information available"
        echo ""
        
        echo "=== SAMPLE PACKETS ==="
        tcpdump -r "$pcap_file" -n -tttt | head -20
    } > "$output_file"
}

# Function to generate JSON statistics
generate_json_stats() {
    local pcap_file="$1"
    local output_file="$2"
    
    print_status "Generating JSON statistics..."
    
    # Basic stats
    local total_packets=$(tcpdump -r "$pcap_file" -n | wc -l)
    local file_size=$(stat -c %s "$pcap_file")
    local file_modified=$(stat -c %Y "$pcap_file")
    
    # Protocol breakdown
    local protocol_stats=$(tcpdump -r "$pcap_file" -n 2>/dev/null | \
        grep -o "proto [A-Z]*" | sort | uniq -c | \
        awk '{print "{\"protocol\":\""$2"\",\"count\":"$1"}"}' | \
        paste -sd, -)
    
    # Port analysis
    local port_stats=$(tcpdump -r "$pcap_file" -n 2>/dev/null | \
        grep -o ":[0-9]*" | sort | uniq -c | sort -nr | head -5 | \
        awk '{print "{\"port\":"$2",\"count\":"$1"}"}' | \
        paste -sd, -)
    
    # IP analysis
    local ip_stats=$(tcpdump -r "$pcap_file" -n 2>/dev/null | \
        grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort | uniq -c | sort -nr | head -5 | \
        awk '{print "{\"ip\":\""$2"\",\"count\":"$1"}"}' | paste -sd, -)
    
    cat > "$output_file" << EOF
{
  "file_info": {
    "filename": "$(basename "$pcap_file")",
    "size_bytes": $file_size,
    "modified_timestamp": $file_modified,
    "total_packets": $total_packets
  },
  "protocols": [$protocol_stats],
  "top_ports": [$port_stats],
  "top_ips": [$ip_stats],
  "analysis_timestamp": $(date +%s)
}
EOF
}

# Function to generate full JSON analysis
generate_full_json() {
    local pcap_file="$1"
    local output_file="$2"
    
    print_status "Generating full JSON analysis..."
    
    # Use tshark if available for detailed analysis
    if command -v tshark &> /dev/null; then
        # Get basic packet count
        local total_packets=$(tshark -r "$pcap_file" -q -z io,stat,0 2>/dev/null | grep -E "^[0-9]+" | head -1 | awk '{print $1}' || echo "0")
        
        # Get HTTP request count
        local http_requests=$(tshark -r "$pcap_file" -Y 'http.request' -q -z io,stat,0 2>/dev/null | grep -E "^[0-9]+" | head -1 | awk '{print $1}' || echo "0")
        
        # Get TCP packet count
        local tcp_packets=$(tshark -r "$pcap_file" -Y 'tcp' -q -z io,stat,0 2>/dev/null | grep -E "^[0-9]+" | head -1 | awk '{print $1}' || echo "0")
        
        # Generate JSON with proper error handling
        {
            echo "{"
            echo "  \"analysis_info\": {"
            echo "    \"filename\": \"$(basename "$pcap_file")\","
            echo "    \"analysis_timestamp\": $(date +%s),"
            echo "    \"total_packets\": \"$total_packets\""
            echo "  },"
            echo "  \"protocol_summary\": {"
            echo "    \"http_requests\": \"$http_requests\","
            echo "    \"tcp_packets\": \"$tcp_packets\""
            echo "  },"
            echo "  \"http_requests\": ["
            
            # Extract HTTP requests with proper JSON formatting
            local http_data=$(tshark -r "$pcap_file" -Y 'http.request' -T fields -e http.request.method -e http.request.uri -e http.host 2>/dev/null | head -10)
            if [ -n "$http_data" ]; then
                echo "$http_data" | awk -F'\t' '{
                    if ($1 != "" && $2 != "") {
                        gsub(/"/, "\\\"", $1)
                        gsub(/"/, "\\\"", $2)
                        gsub(/"/, "\\\"", $3)
                        print "    {\"method\":\""$1"\",\"uri\":\""$2"\",\"host\":\""$3"\"},"
                    }
                }' | sed '$s/,$//'
            fi
            
            echo "  ],"
            echo "  \"top_ips\": ["
            
            # Extract top IP addresses
            local ip_data=$(tshark -r "$pcap_file" -q -z hosts,ip 2>/dev/null | tail -n +3 | head -5)
            if [ -n "$ip_data" ]; then
                echo "$ip_data" | awk '{
                    if ($1 != "" && $2 != "") {
                        gsub(/"/, "\\\"", $1)
                        gsub(/"/, "\\\"", $2)
                        print "    {\"ip\":\""$1"\",\"packets\":\""$2"\"},"
                    }
                }' | sed '$s/,$//'
            fi
            
            echo "  ]"
            echo "}"
        } > "$output_file" || {
            echo "{\"error\": \"Failed to generate detailed JSON analysis\"}" > "$output_file"
        }
    else
        echo "{\"error\": \"tshark not available for detailed analysis\"}" > "$output_file"
    fi
}

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS] [PCAP_FILE]

Options:
    -f, --format FORMAT    Output format (summary, http, detailed, json, stats, all)
    -o, --output DIR       Output directory (default: ./output)
    -l, --latest          Use latest moderate experiment automatically
    -h, --help            Show this help message

Formats:
    summary    - Packet summary in text format
    http       - HTTP content extraction
    detailed   - Detailed protocol analysis
    json       - Full JSON packet analysis
    stats      - JSON statistics
    all        - Generate all formats (default)

Examples:
    $0 -l                    # Convert latest moderate experiment
    $0 -f summary file.pcap  # Generate summary only
    $0 -o ./results file.pcap # Output to ./results directory
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--format)
            FORMAT="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -l|--latest)
            LATEST_ONLY=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            print_error "Unknown option $1"
            usage
            exit 1
            ;;
        *)
            PCAP_FILE="$1"
            shift
            ;;
    esac
done

# Main execution
main() {
    print_status "Starting pcap conversion..."
    
    # Check dependencies
    check_dependencies
    
    # Determine pcap file
    if [ "$LATEST_ONLY" = true ]; then
        local latest_dir=$(find_latest_moderate)
        PCAP_FILE=$(find_pcap_file "$latest_dir")
        print_status "Using latest moderate experiment: $PCAP_FILE"
    elif [ -z "$PCAP_FILE" ]; then
        print_error "No pcap file specified and --latest not used"
        usage
        exit 1
    fi
    
    # Validate pcap file
    if [ ! -f "$PCAP_FILE" ]; then
        print_error "Pcap file not found: $PCAP_FILE"
        exit 1
    fi
    
    # Set output directory
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="./output/$(basename "$PCAP_FILE" .pcap)_analysis"
    fi
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    print_status "Output directory: $OUTPUT_DIR"
    
    # Generate outputs based on format
    case "$FORMAT" in
        summary)
            generate_summary "$PCAP_FILE" "$OUTPUT_DIR/summary.txt"
            ;;
        http)
            extract_http_content "$PCAP_FILE" "$OUTPUT_DIR/http_content.txt"
            ;;
        detailed)
            generate_detailed_analysis "$PCAP_FILE" "$OUTPUT_DIR/detailed_analysis.txt"
            ;;
        json)
            generate_full_json "$PCAP_FILE" "$OUTPUT_DIR/full_analysis.json"
            ;;
        stats)
            generate_json_stats "$PCAP_FILE" "$OUTPUT_DIR/packet_stats.json"
            ;;
        all)
            generate_summary "$PCAP_FILE" "$OUTPUT_DIR/summary.txt"
            extract_http_content "$PCAP_FILE" "$OUTPUT_DIR/http_content.txt"
            generate_detailed_analysis "$PCAP_FILE" "$OUTPUT_DIR/detailed_analysis.txt"
            generate_json_stats "$PCAP_FILE" "$OUTPUT_DIR/packet_stats.json"
            generate_full_json "$PCAP_FILE" "$OUTPUT_DIR/full_analysis.json"
            ;;
        *)
            print_error "Unknown format: $FORMAT"
            usage
            exit 1
            ;;
    esac
    
    print_status "Conversion completed successfully!"
    print_status "Output files in: $OUTPUT_DIR"
    ls -la "$OUTPUT_DIR"
}

# Run main function
main "$@" 