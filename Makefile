# RAS Security Logs Makefile
# Unified management for all RAS scenarios and tasks

# Configuration
RAS_DIR = RAS
SCENARIO = securitylogs
SCENARIO_DIR = $(RAS_DIR)/scenario-$(SCENARIO)
LOG_FILE = $(SCENARIO_DIR)/out/nginx/detailed.log
OUTPUT_DIR = $(SCENARIO_DIR)/out/processed

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[1;33m
BLUE = \033[0;34m
NC = \033[0m # No Color

.PHONY: help start stop restart logs clean day1 day2 day3 day3-process logs-live status

# Default target
help:
	@echo "$(BLUE)============================================================$(NC)"
	@echo "$(BLUE)RAS Security Logs Management Makefile$(NC)"
	@echo "$(BLUE)============================================================$(NC)"
	@echo ""
	@echo "$(GREEN)Environment Management:$(NC)"
	@echo "  make start          - Start RAS environment"
	@echo "  make stop           - Stop RAS environment"
	@echo "  make restart        - Restart RAS environment"
	@echo "  make clean          - Stop and clean all data"
	@echo "  make status         - Show container status"
	@echo ""
	@echo "$(GREEN)Logging & Monitoring:$(NC)"
	@echo "  make logs           - Show container logs"
	@echo "  make logs-live      - Show live logs"
	@echo ""
	@echo "$(GREEN)Day-specific Tasks:$(NC)"
	@echo "  make day1           - Run Day 1: Docker environment migration"
	@echo "  make day2           - Run Day 2: Attack script realization"
	@echo "  make day3           - Run Day 3: Benign traffic & log processing"
	@echo "  make day3-process    - Process existing logs only"
	@echo "  make day3-process-clean - Process logs with NO classification rules"
	@echo ""
	@echo "$(GREEN)Utility Commands:$(NC)"
	@echo "  make fix-permissions - Fix file permissions"
	@echo "  make bridges        - Show available network bridges"
	@echo ""
	@echo "$(GREEN)Attack Script Commands:$(NC)"
	@echo "  make attack-help    - Show attack script help"
	@echo "  make attack-list    - Show attack scenarios file"
	@echo "  make attack-sql     - Execute SQL injection attacks (lines 5-12)"
	@echo "  make attack-xss     - Execute XSS attacks (lines 15-20)"
	@echo "  make attack-traversal - Execute traversal attacks (lines 25-30)"
	@echo "  make attack-custom  - Execute custom range (START=5 END=10)"
	@echo ""
	@echo "$(GREEN)WAF Mode Commands:$(NC)"
	@echo "  make start-waf      - Start environment in WAF mode"
	@echo "  make stop-waf       - Stop WAF environment"
	@echo "  make restart-waf    - Restart WAF environment"
	@echo "  make attack-waf-sql - Execute SQL injection attacks in WAF mode"
	@echo "  make attack-waf-xss - Execute XSS attacks in WAF mode"
	@echo "  make attack-waf-custom - Execute custom range in WAF mode (START=5 END=10)"
	@echo ""
	@echo "$(GREEN)Attack Analysis Commands:$(NC)"
	@echo "  make attack-only [START=1] [END=25] - Run attacks only with custom payload range"
	@echo "  make benign-only       - Run benign traffic only (no attacks)"
	@echo "  make attack-mixed [START=1] [END=25] - Run both attacks and benign traffic with custom payload range"
	@echo "  make attack-all-waf    - Run all attacks in WAF mode"
	@echo "  make attack-analyze-normal - Analyze normal mode attack results"
	@echo "  make attack-analyze-waf    - Analyze WAF mode attack results"
	@echo "  make attack-full-test     - Complete test (both modes + analysis)"
	@echo ""
	@echo "$(GREEN)Data Analysis Commands:$(NC)"
	@echo "  make analyze-attack-only - Analyze attack-only results"
	@echo "  make analyze-benign-only - Analyze benign-only results"
	@echo "  make analyze-mixed      - Analyze mixed mode results"
	@echo "  make data-summary       - Show data summary for all modes"
	@echo ""
	@echo "$(GREEN)Data Management Commands:$(NC)"
	@echo "  make clean-attack-only  - Clean attack-only data"
	@echo "  make clean-benign-only  - Clean benign-only data"
	@echo "  make clean-mixed        - Clean mixed mode data"

# Environment Management
start:
	@echo "$(BLUE)Starting RAS environment (normal mode)...$(NC)"
	cd $(RAS_DIR) && ./ras.sh $(SCENARIO) start

start-waf:
	@echo "$(BLUE)Starting RAS environment (WAF mode)...$(NC)"
	cd $(RAS_DIR) && ./ras.sh waf start

stop:
	@echo "$(YELLOW)Stopping RAS environment...$(NC)"
	cd $(RAS_DIR) && ./ras.sh $(SCENARIO) stop

stop-waf:
	@echo "$(YELLOW)Stopping RAS environment (WAF mode)...$(NC)"
	cd $(RAS_DIR) && ./ras.sh waf stop

restart:
	@echo "$(BLUE)Restarting RAS environment...$(NC)"
	cd $(RAS_DIR) && ./ras.sh $(SCENARIO) restart

restart-waf:
	@echo "$(BLUE)Restarting RAS environment (WAF mode)...$(NC)"
	cd $(RAS_DIR) && ./ras.sh waf restart

clean:
	@echo "$(RED)Cleaning RAS environment and all experiment data...$(NC)"
	@echo "$(YELLOW)Step 1: Stopping and cleaning containers...$(NC)"
	cd $(RAS_DIR) && ./ras.sh $(SCENARIO) clean
	@echo "$(YELLOW)Step 2: Cleaning network captures...$(NC)"
	@sudo $(SCENARIO_DIR)/scripts/network_capture.sh --clean 2>/dev/null || true
	@echo "$(YELLOW)Step 3: Removing all experiment results...$(NC)"
	@rm -rf $(SCENARIO_DIR)/out/results/* 2>/dev/null || true
	@echo "$(YELLOW)Step 4: Cleaning individual log files...$(NC)"
	@rm -f $(SCENARIO_DIR)/out/nginx/*.log 2>/dev/null || true
	@rm -f $(SCENARIO_DIR)/out/attacker/* 2>/dev/null || true
	@rm -f $(SCENARIO_DIR)/out/user/* 2>/dev/null || true
	@rm -rf $(OUTPUT_DIR)/* 2>/dev/null || true
	@echo "$(YELLOW)Step 5: Removing temporary Docker networks...$(NC)"
	@docker network rm scenario-securitylogs_edge scenario-securitylogs_appnet 2>/dev/null || true
	@docker network rm ras-securitylogs-edge ras-securitylogs-appnet 2>/dev/null || true
	@echo "$(GREEN)✅ All experiment data cleaned successfully!$(NC)"

status:
	@echo "$(BLUE)Container Status:$(NC)"
	docker ps --filter "name=ras-$(SCENARIO)" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Logging & Monitoring
logs:
	@echo "$(BLUE)Container Logs:$(NC)"
	cd $(RAS_DIR) && ./ras.sh $(SCENARIO) logs

logs-live:
	@echo "$(BLUE)Live Logs (Press Ctrl+C to stop):$(NC)"
	@tail -f $(LOG_FILE)

# Day 1: Docker Environment Migration
day1:
	@echo "$(BLUE)============================================================$(NC)"
	@echo "$(BLUE)DAY 1: DOCKER ENVIRONMENT MIGRATION$(NC)"
	@echo "$(BLUE)============================================================$(NC)"
	@echo "$(GREEN)Step 1: Starting RAS environment...$(NC)"
	$(MAKE) start
	@echo "$(GREEN)Step 2: Waiting for containers to initialize...$(NC)"
	@sleep 30
	@echo "$(GREEN)Step 3: Checking container status...$(NC)"
	$(MAKE) status
	@echo "$(GREEN)Step 4: Verifying attack script execution...$(NC)"
	@sleep 60
	@echo "$(GREEN)Day 1 completed! Check logs for attack execution.$(NC)"

# Day 2: Attack Script Realization
day2:
	@echo "$(BLUE)============================================================$(NC)"
	@echo "$(BLUE)DAY 2: ATTACK SCRIPT REALIZATION$(NC)"
	@echo "$(BLUE)============================================================$(NC)"
	@echo "$(GREEN)Step 1: Ensuring environment is running...$(NC)"
	$(MAKE) start
	@echo "$(GREEN)Step 2: Waiting for attack execution...$(NC)"
	@sleep 90
	@echo "$(GREEN)Step 3: Checking attack logs...$(NC)"
	@echo "$(YELLOW)Recent attack logs:$(NC)"
	@tail -10 $(LOG_FILE) | grep -E "(attacker|sqlmap|nmap|dirb)" || echo "No attack logs found yet"
	@echo "$(GREEN)Day 2 completed! Attack scripts should be running.$(NC)"

# Day 3: Benign Traffic & Log Processing
day3:
	@echo "$(BLUE)============================================================$(NC)"
	@echo "$(BLUE)DAY 3: BENIGN TRAFFIC & LOG PROCESSING$(NC)"
	@echo "$(BLUE)============================================================$(NC)"
	@echo "$(GREEN)Step 1: Starting environment with benign traffic...$(NC)"
	$(MAKE) start
	@echo "$(GREEN)Step 2: Waiting for traffic generation...$(NC)"
	@sleep 120
	@echo "$(GREEN)Step 3: Processing logs...$(NC)"
	$(MAKE) day3-process
	@echo "$(GREEN)Day 3 completed! Check $(OUTPUT_DIR) for processed data.$(NC)"

# Day 3: Process logs only
day3-process:
	@echo "$(BLUE)Processing logs...$(NC)"
	@mkdir -p $(OUTPUT_DIR)
	@if [ ! -f $(LOG_FILE) ]; then \
		echo "$(RED)Error: Log file not found: $(LOG_FILE)$(NC)"; \
		exit 1; \
	fi
	@echo "$(GREEN)Processing $(shell wc -l < $(LOG_FILE)) log entries...$(NC)"
	cd $(SCENARIO_DIR) && python3 scripts/log_processor.py out/nginx/detailed.log \
		--output-csv out/processed/day3_processed_logs.csv \
		--output-json out/processed/day3_processed_logs.json
	@echo "$(GREEN)Log processing completed!$(NC)"
	@echo "$(YELLOW)Generated files:$(NC)"
	@ls -la $(OUTPUT_DIR)/

# Day 3: Process logs with clean classification (no rules)
day3-process-clean:
	@echo "$(BLUE)Processing logs with clean classification (no rules)...$(NC)"
	@mkdir -p $(OUTPUT_DIR)
	@if [ ! -f $(LOG_FILE) ]; then \
		echo "$(RED)Error: Log file not found: $(LOG_FILE)$(NC)"; \
		exit 1; \
	fi
	@echo "$(GREEN)Processing $(shell wc -l < $(LOG_FILE)) log entries with NO classification rules...$(NC)"
	cd $(SCENARIO_DIR) && python3 scripts/log_processor_clean.py out/nginx/detailed.log \
		--output-csv out/processed/day3_clean_processed_logs.csv \
		--output-json out/processed/day3_clean_processed_logs.json
	@echo "$(GREEN)Clean log processing completed!$(NC)"
	@echo "$(YELLOW)Generated files:$(NC)"
	@ls -la $(OUTPUT_DIR)/

# Process logs with limits
day3-process-limit:
	@echo "$(BLUE)Processing logs with limit...$(NC)"
	@mkdir -p $(OUTPUT_DIR)
	@if [ ! -f $(LOG_FILE) ]; then \
		echo "$(RED)Error: Log file not found: $(LOG_FILE)$(NC)"; \
		exit 1; \
	fi
	@echo "$(GREEN)Processing first 100 log entries...$(NC)"
	cd $(SCENARIO_DIR) && python3 scripts/log_processor.py out/nginx/detailed.log \
		--limit 100 \
		--output-csv out/processed/day3_processed_logs_100.csv \
		--output-json out/processed/day3_processed_logs_100.json
	@echo "$(GREEN)Log processing completed!$(NC)"

# Process logs with sampling
day3-process-sample:
	@echo "$(BLUE)Processing logs with sampling...$(NC)"
	@mkdir -p $(OUTPUT_DIR)
	@if [ ! -f $(LOG_FILE) ]; then \
		echo "$(RED)Error: Log file not found: $(LOG_FILE)$(NC)"; \
		exit 1; \
	fi
	@echo "$(GREEN)Processing 50 random log entries...$(NC)"
	cd $(SCENARIO_DIR) && python3 scripts/log_processor.py out/nginx/detailed.log \
		--sample 50 \
		--output-csv out/processed/day3_processed_logs_sample.csv \
		--output-json out/processed/day3_processed_logs_sample.json
	@echo "$(GREEN)Log processing completed!$(NC)"

# Utility Commands
fix-permissions:
	@echo "$(BLUE)Fixing file permissions...$(NC)"
	cd $(RAS_DIR) && ./ras.sh $(SCENARIO) fix-permissions

bridges:
	@echo "$(BLUE)Available network bridges:$(NC)"
	cd $(RAS_DIR) && ./ras.sh $(SCENARIO) bridges

# Quick access to specific containers
logs-attacker:
	@echo "$(BLUE)Attacker container logs:$(NC)"
	docker logs -f ras-$(SCENARIO)-attacker-1

logs-user:
	@echo "$(BLUE)User container logs:$(NC)"
	docker logs -f ras-$(SCENARIO)-user-1

logs-nginx:
	@echo "$(BLUE)Nginx container logs:$(NC)"
	docker logs -f ras-$(SCENARIO)-nginx-1

# Quick stats
stats:
	@echo "$(BLUE)Log Statistics:$(NC)"
	@if [ -f $(LOG_FILE) ]; then \
		echo "Total log entries: $(shell wc -l < $(LOG_FILE))"; \
		echo "Attack entries: $(shell grep -c "attacker\|sqlmap\|nmap\|dirb" $(LOG_FILE) || echo "0")"; \
		echo "Benign entries: $(shell grep -c "Mozilla\|Chrome\|Firefox\|Safari" $(LOG_FILE) || echo "0")"; \
	else \
		echo "$(RED)Log file not found: $(LOG_FILE)$(NC)"; \
	fi

# Development helpers
dev-restart:
	@echo "$(BLUE)Development restart (quick)...$(NC)"
	$(MAKE) stop
	@sleep 5
	$(MAKE) start

dev-logs:
	@echo "$(BLUE)Development logs (all containers)...$(NC)"
	docker-compose -f $(SCENARIO_DIR)/docker-compose.yml logs -f

# Cleanup helpers
clean-logs:
	@echo "$(YELLOW)Cleaning log files...$(NC)"
	@rm -f $(SCENARIO_DIR)/out/nginx/*.log
	@rm -f $(SCENARIO_DIR)/out/attacker/*
	@rm -f $(SCENARIO_DIR)/out/user/*
	@rm -rf $(OUTPUT_DIR)/*

clean-all:
	@echo "$(RED)Cleaning everything...$(NC)"
	$(MAKE) clean
	$(MAKE) clean-logs

# New log viewing commands
logs-attack-script:
	@echo "$(BLUE)Attack script output log:$(NC)"
	@if [ -f $(SCENARIO_DIR)/out/attacker/attack.log ]; then \
		tail -50 $(SCENARIO_DIR)/out/attacker/attack.log; \
	else \
		echo "$(RED)Attack log not found$(NC)"; \
	fi

logs-network:
	@echo "$(BLUE)Network capture files:$(NC)"
	@if [ -d $(SCENARIO_DIR)/out/network ]; then \
		ls -la $(SCENARIO_DIR)/out/network/; \
	else \
		echo "$(RED)Network capture directory not found$(NC)"; \
	fi

logs-benign:
	@echo "$(BLUE)Benign traffic log:$(NC)"
	@if [ -f $(SCENARIO_DIR)/out/user/benign_traffic.log ]; then \
		tail -20 $(SCENARIO_DIR)/out/user/benign_traffic.log; \
	else \
		echo "$(RED)Benign traffic log not found$(NC)"; \
	fi

# Anti-pollution experiment commands
experiment-attack:
	@echo "$(BLUE)Running attack experiment...$(NC)"
	@sudo $(SCENARIO_DIR)/scripts/experiment_controller.sh --name attack-$(shell date +%Y%m%d-%H%M%S) --type attack --action run --duration 600

experiment-benign:
	@echo "$(BLUE)Running benign experiment...$(NC)"
	@sudo $(SCENARIO_DIR)/scripts/experiment_controller.sh --name benign-$(shell date +%Y%m%d-%H%M%S) --type benign --action run --duration 300

experiment-mixed:
	@echo "$(BLUE)Running mixed experiment...$(NC)"
	@sudo $(SCENARIO_DIR)/scripts/experiment_controller.sh --name mixed-$(shell date +%Y%m%d-%H%M%S) --type mixed --action run --duration 900

# Individual experiment control commands
experiment-start:
	@echo "$(BLUE)Starting experiment environment...$(NC)"
	@sudo $(SCENARIO_DIR)/scripts/experiment_controller.sh --type $(or $(TYPE),attack) --action start

experiment-stop:
	@echo "$(BLUE)Stopping experiment environment...$(NC)"
	@sudo $(SCENARIO_DIR)/scripts/experiment_controller.sh --type $(or $(TYPE),attack) --action stop

experiment-status:
	@echo "$(BLUE)Experiment status...$(NC)"
	@$(SCENARIO_DIR)/scripts/experiment_controller.sh --type $(or $(TYPE),attack) --action status

# Network capture management
capture-start:
	@echo "$(BLUE)Starting network capture...$(NC)"
	@sudo $(SCENARIO_DIR)/scripts/network_capture.sh --start $(shell date +%Y%m%d-%H%M%S)

capture-stop:
	@echo "$(BLUE)Stopping network capture...$(NC)"
	@sudo $(SCENARIO_DIR)/scripts/network_capture.sh --stop

capture-list:
	@echo "$(BLUE)Listing network captures...$(NC)"
	@$(SCENARIO_DIR)/scripts/network_capture.sh --list

capture-clean:
	@echo "$(BLUE)Cleaning network captures...$(NC)"
	@sudo $(SCENARIO_DIR)/scripts/network_capture.sh --clean

# Bridge network info
bridges-info:
	@echo "$(BLUE)Docker bridge networks:$(NC)"
	@ip link show | grep -E "^[0-9]+: br-" | awk '{print $2}' | sed 's/://'
	@echo "$(BLUE)Docker networks:$(NC)"
	@docker network ls

# Attack script line range execution commands
attack-sql:
	@echo "$(BLUE)Executing SQL injection attacks (lines 5-12)...$(NC)"
	cd $(SCENARIO_DIR) && docker-compose run --rm attacker bash -c "bash /attack.sh --start 5 --end 12"

attack-xss:
	@echo "$(BLUE)Executing XSS attacks (lines 15-20)...$(NC)"
	cd $(SCENARIO_DIR) && docker-compose run --rm attacker bash -c "bash /attack.sh --start 15 --end 20"

attack-traversal:
	@echo "$(BLUE)Executing directory traversal attacks (lines 25-30)...$(NC)"
	cd $(SCENARIO_DIR) && docker-compose run --rm attacker bash -c "bash /attack.sh --start 25 --end 30"

attack-custom:
	@echo "$(BLUE)Executing custom attack range...$(NC)"
	@if [ -z "$(START)" ] || [ -z "$(END)" ]; then \
		echo "$(RED)Usage: make attack-custom START=5 END=10$(NC)"; \
		exit 1; \
	fi
	cd $(SCENARIO_DIR) && docker-compose run --rm attacker bash -c "bash /attack.sh --start $(START) --end $(END)"

attack-help:
	@echo "$(BLUE)Attack script help...$(NC)"
	cd $(SCENARIO_DIR) && docker-compose run --rm attacker bash -c "bash /attack.sh --help"

attack-list:
	@echo "$(BLUE)Attack scenarios file content...$(NC)"
	@cat $(SCENARIO_DIR)/confs/attacker/attack_scripts/attacks.txt

# WAF Mode Attack Script Commands
attack-waf-sql:
	@echo "$(BLUE)Executing SQL injection attacks in WAF mode (lines 5-12)...$(NC)"
	cd $(RAS_DIR)/scenario-waf && docker-compose run --rm attacker bash -c "bash /attack.sh --start 5 --end 12"

attack-waf-xss:
	@echo "$(BLUE)Executing XSS attacks in WAF mode (lines 15-20)...$(NC)"
	cd $(RAS_DIR)/scenario-waf && docker-compose run --rm attacker bash -c "bash /attack.sh --start 15 --end 20"

attack-waf-traversal:
	@echo "$(BLUE)Executing directory traversal attacks in WAF mode (lines 25-30)...$(NC)"
	cd $(RAS_DIR)/scenario-waf && docker-compose run --rm attacker bash -c "bash /attack.sh --start 25 --end 30"

attack-waf-custom:
	@echo "$(BLUE)Executing custom attack range in WAF mode...$(NC)"
	@if [ -z "$(START)" ] || [ -z "$(END)" ]; then \
		echo "$(RED)Usage: make attack-waf-custom START=5 END=10$(NC)"; \
		exit 1; \
	fi
	cd $(RAS_DIR)/scenario-waf && docker-compose run --rm attacker bash -c "bash /attack.sh --start $(START) --end $(END)"

attack-waf-help:
	@echo "$(BLUE)Attack script help (WAF mode)...$(NC)"
	cd $(RAS_DIR)/scenario-waf && docker-compose run --rm attacker bash -c "bash /attack.sh --help"

# Run attacks only (no benign traffic)
# Usage: make attack-only [START=1] [END=25]
attack-only:
	@echo "$(BLUE)Running attacks only (no benign traffic)...$(NC)"
	@echo "$(YELLOW)Payload range: $(or $(START),1) to $(or $(END),25)$(NC)"
	@echo "$(YELLOW)Step 1: Creating attack-only data directory...$(NC)"
	@mkdir -p $(SCENARIO_DIR)/out/attack-only/nginx
	@mkdir -p $(SCENARIO_DIR)/out/attack-only/attacker
	@mkdir -p $(SCENARIO_DIR)/out/attack-only/pcap
	@echo "$(YELLOW)Step 2: Starting environment with attack-only configuration...$(NC)"
	cd $(SCENARIO_DIR) && MODE=attack-only docker-compose --profile attack-only up -d nginx web
	@sleep 5
	@echo "$(YELLOW)Step 3: Starting network capture...$(NC)"
	@sudo MODE=attack-only $(SCENARIO_DIR)/scripts/network_capture.sh --start attack-only-$(shell date +%Y%m%d-%H%M%S)
	@sleep 30
	@echo "$(YELLOW)Step 4: Executing attacks from line $(or $(START),1) to $(or $(END),25)...$(NC)"
	cd $(SCENARIO_DIR) && MODE=attack-only docker-compose --profile attack-only run --rm attacker bash -c "apt-get update && apt-get install -y curl sqlmap dirb nmap && bash /attack.sh --target http://fancystore.com --start $(or $(START),1) --end $(or $(END),25)"
	@sleep 60
	@echo "$(YELLOW)Step 5: Stopping network capture...$(NC)"
	@sudo MODE=attack-only $(SCENARIO_DIR)/scripts/network_capture.sh --stop
	@echo "$(YELLOW)Step 6: Stopping environment...$(NC)"
	cd $(SCENARIO_DIR) && MODE=attack-only docker-compose --profile attack-only down
	@echo "$(GREEN)Attack-only mode completed!$(NC)"
	@echo "$(BLUE)Data saved to: $(SCENARIO_DIR)/out/attack-only/$(NC)"

# Run benign traffic only (no attacks)
benign-only:
	@echo "$(BLUE)Running benign traffic only (no attacks)...$(NC)"
	@echo "$(YELLOW)Step 1: Creating benign-only data directory...$(NC)"
	@mkdir -p $(SCENARIO_DIR)/out/benign-only/{nginx,attacker,user,logs,pcap}
	@echo "$(YELLOW)Step 2: Starting environment with benign-only configuration...$(NC)"
	cd $(SCENARIO_DIR) && MODE=benign-only docker-compose --profile benign-only up -d nginx web
	@sleep 5
	@echo "$(YELLOW)Step 3: Starting network capture...$(NC)"
	@sudo MODE=benign-only $(SCENARIO_DIR)/scripts/network_capture.sh --start benign-only-$(shell date +%Y%m%d-%H%M%S)
	@sleep 30
	@echo "$(YELLOW)Step 4: Executing benign traffic...$(NC)"
	cd $(SCENARIO_DIR) && MODE=benign-only docker-compose --profile benign-only run --rm user bash -c "pip install requests && python /benign_enhanced.py http://fancystore.com"
	@sleep 60
	@echo "$(YELLOW)Step 5: Stopping network capture...$(NC)"
	@sudo MODE=benign-only $(SCENARIO_DIR)/scripts/network_capture.sh --stop
	@echo "$(YELLOW)Step 6: Stopping environment...$(NC)"
	cd $(SCENARIO_DIR) && MODE=benign-only docker-compose --profile benign-only down
	@echo "$(GREEN)Benign-only mode completed!$(NC)"
	@echo "$(BLUE)Data saved to: $(SCENARIO_DIR)/out/benign-only/$(NC)"

# Run both attacks and benign traffic (mixed mode)
# Usage: make attack-mixed [START=1] [END=25]
attack-mixed:
	@echo "$(BLUE)Running mixed mode (attacks + benign traffic)...$(NC)"
	@echo "$(YELLOW)Payload range: $(or $(START),1) to $(or $(END),25)$(NC)"
	@echo "$(YELLOW)Step 1: Creating mixed data directory...$(NC)"
	@mkdir -p $(SCENARIO_DIR)/out/mixed/{nginx,attacker,user,logs,pcap}
	@echo "$(YELLOW)Step 2: Starting environment with mixed configuration...$(NC)"
	cd $(SCENARIO_DIR) && MODE=mixed docker-compose --profile mixed up -d
	@sleep 5
	@echo "$(YELLOW)Step 3: Starting network capture...$(NC)"
	@sudo MODE=mixed $(SCENARIO_DIR)/scripts/network_capture.sh --start mixed-$(shell date +%Y%m%d-%H%M%S)
	@sleep 30
	@echo "$(YELLOW)Step 4: Executing mixed traffic...$(NC)"
	cd $(SCENARIO_DIR) && MODE=mixed docker-compose --profile mixed run --rm attacker bash -c "apt-get update && apt-get install -y curl sqlmap dirb nmap && bash /attack.sh --target http://fancystore.com --start $(or $(START),1) --end $(or $(END),25)" &
	cd $(SCENARIO_DIR) && MODE=mixed docker-compose --profile mixed run --rm user bash -c "pip install requests && python /benign_enhanced.py http://fancystore.com" &
	@wait
	@sleep 60
	@echo "$(YELLOW)Step 5: Stopping network capture...$(NC)"
	@sudo MODE=mixed $(SCENARIO_DIR)/scripts/network_capture.sh --stop
	@echo "$(YELLOW)Step 6: Stopping environment...$(NC)"
	cd $(SCENARIO_DIR) && MODE=mixed docker-compose --profile mixed down
	@echo "$(GREEN)Mixed mode completed!$(NC)"
	@echo "$(BLUE)Data saved to: $(SCENARIO_DIR)/out/mixed/$(NC)"

# Run attacks with custom line range (usage: make attack-range START=1 END=25)
attack-range:
	@echo "$(BLUE)Running attacks with custom range (lines $(START) to $(END))...$(NC)"
	@echo "$(YELLOW)Step 1: Creating attack-range data directory...$(NC)"
	@mkdir -p $(SCENARIO_DIR)/out/attack-range/{nginx,attacker,user,logs,pcap}
	@echo "$(YELLOW)Step 2: Starting environment...$(NC)"
	cd $(SCENARIO_DIR) && MODE=attack-range docker-compose --profile attack-only up -d nginx web
	@sleep 30
	@echo "$(YELLOW)Step 3: Executing attacks from line $(START) to $(END)...$(NC)"
	cd $(SCENARIO_DIR) && MODE=attack-range docker-compose --profile attack-only run --rm attacker bash -c "apt-get update && apt-get install -y curl sqlmap dirb nmap && bash /attack.sh --target http://fancystore.com --start $(START) --end $(END)"
	@sleep 60
	@echo "$(YELLOW)Step 4: Stopping environment...$(NC)"
	cd $(SCENARIO_DIR) && MODE=attack-range docker-compose --profile attack-only down
	@echo "$(GREEN)Attack-range mode completed!$(NC)"
	@echo "$(BLUE)Data saved to: $(SCENARIO_DIR)/out/attack-range/$(NC)"

# Legacy target for backward compatibility
attack-all-normal:
	@echo "$(YELLOW)Legacy target - use 'make attack-mixed' instead$(NC)"
	$(MAKE) attack-mixed

attack-analyze-normal:
	@echo "$(BLUE)Analyzing attack results in normal mode...$(NC)"
	@mkdir -p $(SCENARIO_DIR)/out/analysis
	@python3 $(SCENARIO_DIR)/scripts/audit_analyzer.py attack \
		--mode normal \
		--attack-log $(SCENARIO_DIR)/out/attacker/attack.log \
		--nginx-log $(SCENARIO_DIR)/out/nginx/access.log \
		--output-dir $(SCENARIO_DIR)/out/analysis/normal_$(shell date +%Y%m%d-%H%M%S)

attack-analyze-waf:
	@echo "$(BLUE)Analyzing attack results in WAF mode...$(NC)"
	@mkdir -p $(RAS_DIR)/scenario-waf/out/analysis
	@python3 $(SCENARIO_DIR)/scripts/audit_analyzer.py attack \
		--mode waf \
		--attack-log $(RAS_DIR)/scenario-waf/out/waf/attacker/attack.log \
		--nginx-log $(RAS_DIR)/scenario-waf/out/waf/nginx/access.log \
		--modsec-log $(RAS_DIR)/scenario-waf/out/waf/modsecurity/audit.log \
		--output-dir $(RAS_DIR)/scenario-waf/out/analysis/waf_$(shell date +%Y%m%d-%H%M%S)

attack-full-test:
	@echo "$(BLUE)Running complete attack test (both modes)...$(NC)"
	@echo "$(YELLOW)Phase 1: Normal mode attacks...$(NC)"
	$(MAKE) attack-all-normal
	@echo "$(YELLOW)Phase 2: WAF mode attacks...$(NC)"
	$(MAKE) attack-all-waf
	@echo "$(YELLOW)Phase 3: Analyzing results...$(NC)"
	$(MAKE) attack-analyze-normal
	$(MAKE) attack-analyze-waf
	@echo "$(GREEN)Complete attack test finished!$(NC)"
	@echo "$(BLUE)Check analysis directories for detailed reports$(NC)"

# Analysis targets for different modes
analyze-attack-only:
	@echo "$(BLUE)Analyzing attack-only results...$(NC)"
	@if [ ! -f "$(SCENARIO_DIR)/out/attack-only/attacker/attack.log" ]; then \
		echo "$(RED)Error: Attack log not found. Run 'make attack-only' first.$(NC)"; \
		exit 1; \
	fi
	@mkdir -p $(SCENARIO_DIR)/out/analysis/attack-only
	@echo "$(YELLOW)Running rule-based attack detection...$(NC)"
	@python3 $(SCENARIO_DIR)/scripts/attack_detector.py \
		--rules $(SCENARIO_DIR)/confs/attacker/detection_rules.yaml \
		--attack-log $(SCENARIO_DIR)/out/attack-only/attacker/attack.log \
		--nginx-log $(SCENARIO_DIR)/out/attack-only/nginx/detailed.log \
		--json-output-dir /tmp/sqlmap_attack \
		--json $(SCENARIO_DIR)/out/analysis/attack-only/attack_detection_results.json
	@echo "$(YELLOW)Running traditional log analysis...$(NC)"
	@python3 $(SCENARIO_DIR)/scripts/log_processor.py $(SCENARIO_DIR)/out/attack-only/nginx/detailed.log --output-csv $(SCENARIO_DIR)/out/analysis/attack-only/log_analysis.csv --output-json $(SCENARIO_DIR)/out/analysis/attack-only/log_analysis.json
	@echo "$(GREEN)Attack-only analysis completed!$(NC)"
	@echo "$(BLUE)JSON results: $(SCENARIO_DIR)/out/analysis/attack-only/attack_detection_results.json$(NC)"

analyze-benign-only:
	@echo "$(BLUE)Analyzing benign-only results...$(NC)"
	@mkdir -p $(SCENARIO_DIR)/out/analysis/benign-only
	@python3 $(SCENARIO_DIR)/scripts/log_processor.py $(SCENARIO_DIR)/out/benign-only/nginx/detailed.log --output $(SCENARIO_DIR)/out/analysis/benign-only/
	@echo "$(GREEN)Benign-only analysis completed!$(NC)"

analyze-mixed:
	@echo "$(BLUE)Analyzing mixed mode results...$(NC)"
	@mkdir -p $(SCENARIO_DIR)/out/analysis/mixed
	@python3 $(SCENARIO_DIR)/scripts/log_processor.py $(SCENARIO_DIR)/out/mixed/nginx/detailed.log --output $(SCENARIO_DIR)/out/analysis/mixed/
	@echo "$(GREEN)Mixed mode analysis completed!$(NC)"

# Clean specific mode data
clean-attack-only:
	@echo "$(YELLOW)Cleaning attack-only data...$(NC)"
	@rm -rf $(SCENARIO_DIR)/out/attack-only
	@rm -rf $(SCENARIO_DIR)/out/analysis/attack-only
	@echo "$(GREEN)Attack-only data cleaned!$(NC)"

clean-benign-only:
	@echo "$(YELLOW)Cleaning benign-only data...$(NC)"
	@rm -rf $(SCENARIO_DIR)/out/benign-only
	@rm -rf $(SCENARIO_DIR)/out/analysis/benign-only
	@echo "$(GREEN)Benign-only data cleaned!$(NC)"

clean-mixed:
	@echo "$(YELLOW)Cleaning mixed mode data...$(NC)"
	@rm -rf $(SCENARIO_DIR)/out/mixed
	@rm -rf $(SCENARIO_DIR)/out/analysis/mixed
	@echo "$(GREEN)Mixed mode data cleaned!$(NC)"

# Show data summary
data-summary:
	@echo "$(BLUE)=== Data Summary ===$(NC)"
	@echo "$(GREEN)Attack-only data:$(NC)"
	@if [ -d "$(SCENARIO_DIR)/out/attack-only" ]; then \
		echo "  - Nginx logs: $(shell wc -l < $(SCENARIO_DIR)/out/attack-only/nginx/detailed.log 2>/dev/null || echo 0) lines"; \
		echo "  - Attack logs: $(shell wc -l < $(SCENARIO_DIR)/out/attack-only/attacker/attack.log 2>/dev/null || echo 0) lines"; \
	else \
		echo "  - No data found"; \
	fi
	@echo "$(GREEN)Benign-only data:$(NC)"
	@if [ -d "$(SCENARIO_DIR)/out/benign-only" ]; then \
		echo "  - Nginx logs: $(shell wc -l < $(SCENARIO_DIR)/out/benign-only/nginx/detailed.log 2>/dev/null || echo 0) lines"; \
		echo "  - User logs: $(shell wc -l < $(SCENARIO_DIR)/out/benign-only/user/benign_traffic.log 2>/dev/null || echo 0) lines"; \
		else \
		echo "  - No data found"; \
	fi
	@echo "$(GREEN)Mixed mode data:$(NC)"
	@if [ -d "$(SCENARIO_DIR)/out/mixed" ]; then \
		echo "  - Nginx logs: $(shell wc -l < $(SCENARIO_DIR)/out/mixed/nginx/detailed.log 2>/dev/null || echo 0) lines"; \
		echo "  - Attack logs: $(shell wc -l < $(SCENARIO_DIR)/out/mixed/attacker/attack.log 2>/dev/null || echo 0) lines"; \
		echo "  - User logs: $(shell wc -l < $(SCENARIO_DIR)/out/mixed/user/benign_traffic.log 2>/dev/null || echo 0) lines"; \
		else \
		echo "  - No data found"; \
	fi
