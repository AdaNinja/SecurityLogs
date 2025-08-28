#!/bin/bash

# Unified Attack Script for CyberRange
# Supports multiple attack types and scenarios

# Generate unique log file name
LOG_TIMESTAMP=$(date +%s)
LOG_PID=$$
LOG_FILENAME="attack_${LOG_TIMESTAMP}_${LOG_PID}.log"

# Redirect output to log file
exec > >(tee /logs/${LOG_FILENAME}) 2>&1

# Global variables
TARGET="${TARGET_URL:-http://fancystore.com}"
ATTACK_MODE="${ATTACK_MODE:-basic}"  # basic, advanced, multi-phase
ATTACK_TYPE="${ATTACK_TYPE:-all}"    # specific attack type or all
ATTACK_FILE="${ATTACK_FILE:-}"       # specific payload file
START_LINE="${START_LINE:-1}"        # start line in payload file
END_LINE="${END_LINE:-999}"          # end line in payload file
INTERVAL="${INTERVAL:-5}"            # interval between attacks
USER_AGENT="${USER_AGENT:-attacker}" # user agent for identification

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Log function
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
    echo -e "${timestamp} [${level}] ${message}"
    echo "{\"timestamp\":\"$timestamp\",\"level\":\"$level\",\"message\":\"$message\",\"attack_type\":\"$ATTACK_TYPE\"}" >> /logs/structured_${LOG_FILENAME}
}

# Attack validation functions
validate_sql_injection() {
    local response_body="$1"
    local status_code="$2"
    local attack_id="$3"
    
    # Check for SQL injection indicators
    if [[ "$response_body" =~ (syntax error|mysql_fetch|ORA-[0-9]+|Microsoft.*ODBC.*SQL|PostgreSQL.*ERROR|sqlite3.OperationalError) ]] || \
       [[ "$response_body" =~ (database|schema|table|column) ]] || \
       [[ "$status_code" == "500" ]] || \
       [[ "$response_body" =~ (admin|user|password|email|login) ]]; then
        log "VALIDATION" "SQL injection indicators detected for $attack_id"
        return 0
    fi
    return 1
}

validate_xss_attack() {
    local response_body="$1"
    local status_code="$2"
    local attack_id="$3"
    
    # Check for XSS indicators
    if [[ "$response_body" =~ (<script|<iframe|<img.*onerror|javascript:|alert\(|document\.cookie) ]] || \
       [[ "$status_code" == "201" ]] || \
       [[ "$response_body" =~ (feedback|comment|review) ]]; then
        log "VALIDATION" "XSS attack indicators detected for $attack_id"
        return 0
    fi
    return 1
}

validate_command_injection() {
    local response_body="$1"
    local status_code="$2"
    local attack_id="$3"
    
    # Check for command injection indicators
    if [[ "$status_code" == "500" ]] || \
       [[ "$response_body" =~ (root|bin|usr|tmp|var|etc|proc) ]] || \
       [[ "$response_body" =~ (command|shell|bash|sh) ]]; then
        log "VALIDATION" "Command injection indicators detected for $attack_id"
        return 0
    fi
    return 1
}

validate_directory_traversal() {
    local response_body="$1"
    local status_code="$2"
    local attack_id="$3"
    
    # Check for directory traversal indicators
    if [[ "$response_body" =~ (root:|bin:|usr:|etc/passwd|etc/shadow|windows|system32) ]] || \
       [[ "$status_code" == "200" ]] || \
       [[ "$response_body" =~ (directory|file|path) ]]; then
        log "VALIDATION" "Directory traversal indicators detected for $attack_id"
        return 0
    fi
    return 1
}

validate_auth_bypass() {
    local response_body="$1"
    local status_code="$2"
    local attack_id="$3"
    
    # Check for authentication bypass indicators
    if [[ "$response_body" =~ (token|session|authentication|login|admin|user) ]] || \
       [[ "$status_code" == "200" ]] || \
       [[ "$response_body" =~ (welcome|dashboard|profile) ]]; then
        log "VALIDATION" "Authentication bypass indicators detected for $attack_id"
        return 0
    fi
    return 1
}

validate_file_discovery() {
    local response_body="$1"
    local status_code="$2"
    local attack_id="$3"
    
    # Check for file discovery indicators
    if [[ "$status_code" == "200" ]] || \
       [[ "$response_body" =~ (robots\.txt|\.git|backup|config|env|php) ]] || \
       [[ "$response_body" =~ (file|directory|content) ]]; then
        log "VALIDATION" "File discovery indicators detected for $attack_id"
        return 0
    fi
    return 1
}

validate_method_enumeration() {
    local response_body="$1"
    local status_code="$2"
    local attack_id="$3"
    
    # Check for method enumeration indicators
    if [[ "$status_code" == "204" ]] || [[ "$status_code" == "200" ]] || \
       [[ "$status_code" == "405" ]] || [[ "$status_code" == "501" ]] || \
       [[ "$response_body" =~ (options|trace|put|delete|patch) ]]; then
        log "VALIDATION" "Method enumeration indicators detected for $attack_id"
        return 0
    fi
    return 1
}

# Execute attack from payload file with enhanced validation
execute_payload_attack() {
    local method="$1"
    local endpoint="$2"
    local payload="$3"
    local expected_code="$4"
    local attack_id="$5"
    local description="$6"
    
    log "INFO" "Executing attack: $description (ID: $attack_id)"
    
    # Determine content type based on payload
    local content_type="application/x-www-form-urlencoded"
    if [[ "$payload" =~ ^{.*}$ ]]; then
        content_type="application/json"
    fi
    
    # Execute attack with enhanced logging
    local response=$(curl -s -w "\\n%{http_code}\\n%{time_total}\\n%{size_download}" -X "$method" "$TARGET$endpoint" \
        -H "Content-Type: $content_type" \
        -H "User-Agent: $USER_AGENT" \
        -H "X-Attack-Type: $ATTACK_TYPE" \
        -H "X-Attack-ID: $attack_id" \
        -H "X-Attack-Timestamp: $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" \
        -d "$payload" 2>/dev/null)
    
    # Parse response details
    local lines=($(echo "$response" | tail -3))
    local status_code="${lines[0]}"
    local time_total="${lines[1]}"
    local size_download="${lines[2]}"
    local response_body=$(echo "$response" | head -n -3)
    
    log "INFO" "Response: Status=$status_code, Expected=$expected_code, Time=${time_total}s, Size=${size_download}bytes"
    
    # Enhanced attack validation
    local attack_success=false
    local validation_details=""
    
    # Basic status code check
    if [[ "$status_code" == "$expected_code" ]]; then
        attack_success=true
        validation_details="Status code match"
    fi
    
    # Enhanced validation based on attack type
    case "$ATTACK_TYPE" in
        "sql"|"sql_injection")
            validate_sql_injection "$response_body" "$status_code" "$attack_id"
            if [[ $? -eq 0 ]]; then
                attack_success=true
                validation_details="$validation_details + SQL injection indicators detected"
            fi
            ;;
        "xss")
            validate_xss_attack "$response_body" "$status_code" "$attack_id"
            if [[ $? -eq 0 ]]; then
                attack_success=true
                validation_details="$validation_details + XSS payload executed"
            fi
            ;;
        "cmd"|"command_injection")
            validate_command_injection "$response_body" "$status_code" "$attack_id"
            if [[ $? -eq 0 ]]; then
                attack_success=true
                validation_details="$validation_details + Command injection successful"
            fi
            ;;
        "dir"|"directory_traversal")
            validate_directory_traversal "$response_body" "$status_code" "$attack_id"
            if [[ $? -eq 0 ]]; then
                attack_success=true
                validation_details="$validation_details + Directory traversal successful"
            fi
            ;;
        "auth"|"auth_bypass")
            validate_auth_bypass "$response_body" "$status_code" "$attack_id"
            if [[ $? -eq 0 ]]; then
                attack_success=true
                validation_details="$validation_details + Authentication bypass detected"
            fi
            ;;
        "file"|"file_discovery")
            validate_file_discovery "$response_body" "$status_code" "$attack_id"
            if [[ $? -eq 0 ]]; then
                attack_success=true
                validation_details="$validation_details + File discovery successful"
            fi
            ;;
        "method"|"method_enumeration")
            validate_method_enumeration "$response_body" "$status_code" "$attack_id"
            if [[ $? -eq 0 ]]; then
                attack_success=true
                validation_details="$validation_details + Method enumeration successful"
            fi
            ;;
    esac
    
    # Log validation results
    if [[ "$attack_success" == true ]]; then
        log "SUCCESS" "Attack VALIDATED: $description ($validation_details)"
        echo "ATTACK_SUCCESS|$attack_id|$ATTACK_TYPE|$description|$status_code|$validation_details" >> /logs/attack_validation.log
        # Update global success counter
        echo "$attack_id" >> /tmp/successful_attacks.log
    else
        log "FAILURE" "Attack FAILED: $description (Status: $status_code, Expected: $expected_code)"
        echo "ATTACK_FAILURE|$attack_id|$ATTACK_TYPE|$description|$status_code|No validation criteria met" >> /logs/attack_validation.log
        # Update global failure counter
        echo "$attack_id" >> /tmp/failed_attacks.log
    fi
    
    sleep "$INTERVAL"
}

# Parse and execute attacks from payload file
parse_payload_file() {
    local file_path="$1"
    local attack_filter="$2"
    
    if [[ ! -f "$file_path" ]]; then
        log "ERROR" "Payload file not found: $file_path"
        return 1
    fi
    
    log "INFO" "Loading attacks from: $file_path"
    
    local line_count=0
    while IFS='|' read -r method endpoint payload expected_code attack_id description; do
        # Skip comments and empty lines
        if [[ "$method" =~ ^#.*$ ]] || [[ -z "$method" ]]; then
            continue
        fi
        
        line_count=$((line_count + 1))
        
        # Check line range
        if [[ $line_count -lt $START_LINE ]] || [[ $line_count -gt $END_LINE ]]; then
            continue
        fi
        
        # Filter by attack type if specified
        if [[ -n "$attack_filter" ]] && [[ "$attack_filter" != "all" ]]; then
            if [[ ! "$attack_id" =~ ^${attack_filter}_ ]] && [[ "$description" != *"$attack_filter"* ]]; then
                continue
            fi
        fi
        
        execute_payload_attack "$method" "$endpoint" "$payload" "$expected_code" "$attack_id" "$description"
        
    done < "$file_path"
}

# Execute basic attacks (7 categories)
execute_basic_attacks() {
    log "INFO" "Starting basic attacks (7 categories)"
    
    # Check if we should use category-specific payloads
    if [[ -d "/scripts/attacks/$ATTACK_TYPE" ]] && [[ "$ATTACK_TYPE" != "all" ]]; then
        log "INFO" "Using category-specific payloads from /scripts/attacks/$ATTACK_TYPE/"
        
        # Load all payload files from the category directory
        for payload_file in /scripts/attacks/$ATTACK_TYPE/*.txt; do
            if [[ -f "$payload_file" ]]; then
                log "INFO" "Loading payloads from: $(basename $payload_file)"
                parse_payload_file "$payload_file" "$ATTACK_TYPE"
            fi
        done
    else
        # Load unified attack payloads for all types or when no specific directory exists
        parse_payload_file "/scripts/attacks/unified_attack_payloads.txt" "$ATTACK_TYPE"
    fi
}

# Execute advanced multi-phase attacks
execute_advanced_attacks() {
    log "INFO" "Starting advanced multi-phase attacks"
    
    # Phase 1: Initial Access
    log "INFO" "=== Phase 1: Initial Access ==="
    parse_payload_file "/scripts/attacks/advanced_attack_chains.txt" "phase1"
    
    sleep 10
    
    # Phase 2: Command & Control
    log "INFO" "=== Phase 2: Command & Control ==="
    parse_payload_file "/scripts/attacks/advanced_attack_chains.txt" "phase2"
    
    sleep 10
    
    # Phase 3: Data Exfiltration
    log "INFO" "=== Phase 3: Data Exfiltration ==="
    parse_payload_file "/scripts/attacks/advanced_attack_chains.txt" "phase3"
    
    sleep 10
    
    # Phase 4: Lateral Movement
    log "INFO" "=== Phase 4: Lateral Movement ==="
    parse_payload_file "/scripts/attacks/advanced_attack_chains.txt" "phase4"
}

# Execute custom attacks from specified file
execute_custom_attacks() {
    local custom_file="$1"
    log "INFO" "Starting custom attacks from: $custom_file"
    parse_payload_file "$custom_file" "$ATTACK_TYPE"
}

# Generate attack summary report
generate_attack_summary() {
    local total_attacks=0
    local successful_attacks=0
    local failed_attacks=0
    
    # Count attacks
    if [[ -f "/tmp/successful_attacks.log" ]]; then
        successful_attacks=$(wc -l < /tmp/successful_attacks.log)
    fi
    
    if [[ -f "/tmp/failed_attacks.log" ]]; then
        failed_attacks=$(wc -l < /tmp/failed_attacks.log)
    fi
    
    total_attacks=$((successful_attacks + failed_attacks))
    
    if [[ $total_attacks -gt 0 ]]; then
        local success_rate=$(echo "scale=2; $successful_attacks * 100 / $total_attacks" | bc -l)
        
        log "SUMMARY" "================= ATTACK SUMMARY ================="
        log "SUMMARY" "Attack Type: $ATTACK_TYPE"
        log "SUMMARY" "Total Attacks: $total_attacks"
        log "SUMMARY" "Successful: $successful_attacks"
        log "SUMMARY" "Failed: $failed_attacks"
        log "SUMMARY" "Success Rate: ${success_rate}%"
        log "SUMMARY" "=================================================="
        
        # Generate JSON summary
        cat > "/logs/attack_summary_${ATTACK_TYPE}_$(date +%s).json" << EOF
{
  "attack_summary": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)",
    "attack_type": "$ATTACK_TYPE",
    "attack_mode": "$ATTACK_MODE",
    "target": "$TARGET",
    "total_attacks": $total_attacks,
    "successful_attacks": $successful_attacks,
    "failed_attacks": $failed_attacks,
    "success_rate": $success_rate,
    "log_file": "/logs/${LOG_FILENAME}",
    "validation_log": "/logs/attack_validation.log"
  }
}
EOF
        
        log "INFO" "Attack summary saved to /logs/attack_summary_${ATTACK_TYPE}_$(date +%s).json"
    else
        log "WARNING" "No attacks were executed or logged"
    fi
}

# Main execution logic
main() {
    log "INFO" "================================"
    log "INFO" "CyberRange Unified Attack Script"
    log "INFO" "================================"
    log "INFO" "Target: $TARGET"
    log "INFO" "Mode: $ATTACK_MODE"
    log "INFO" "Type: $ATTACK_TYPE"
    log "INFO" "Interval: ${INTERVAL}s"
    
    # Initialize attack tracking files
    > /tmp/successful_attacks.log
    > /tmp/failed_attacks.log
    > /logs/attack_validation.log
    
    case "$ATTACK_MODE" in
        "basic")
            execute_basic_attacks
            ;;
        "advanced")
            execute_advanced_attacks
            ;;
        "multi-phase")
            execute_advanced_attacks
            ;;
        "custom")
            if [[ -n "$ATTACK_FILE" ]]; then
                execute_custom_attacks "$ATTACK_FILE"
            else
                log "ERROR" "Custom mode requires ATTACK_FILE to be specified"
                exit 1
            fi
            ;;
        *)
            log "ERROR" "Unknown attack mode: $ATTACK_MODE"
            exit 1
            ;;
    esac
    
    # Generate summary report
    generate_attack_summary
    
    log "INFO" "Attack execution completed"
    log "INFO" "Log file: /logs/${LOG_FILENAME}"
    log "INFO" "Validation log: /logs/attack_validation.log"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --target)
            TARGET="$2"
            shift 2
            ;;
        --mode)
            ATTACK_MODE="$2"
            shift 2
            ;;
        --type)
            ATTACK_TYPE="$2"
            shift 2
            ;;
        --file)
            ATTACK_FILE="$2"
            shift 2
            ;;
        --start)
            START_LINE="$2"
            shift 2
            ;;
        --end)
            END_LINE="$2"
            shift 2
            ;;
        --interval)
            INTERVAL="$2"
            shift 2
            ;;
        --help)
            echo "CyberRange Unified Attack Script"
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --target URL       Target URL (default: http://fancystore.com)"
            echo "  --mode MODE        Attack mode: basic, advanced, multi-phase, custom"
            echo "  --type TYPE        Attack type filter (e.g., sql, xss, cmd, all)"
            echo "  --file FILE        Custom payload file (for custom mode)"
            echo "  --start LINE       Start line in payload file"
            echo "  --end LINE         End line in payload file"
            echo "  --interval SEC     Interval between attacks in seconds"
            echo "  --help             Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Execute main function
main
