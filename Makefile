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
	@echo ""
	@echo "$(GREEN)Utility Commands:$(NC)"
	@echo "  make fix-permissions - Fix file permissions"
	@echo "  make bridges        - Show available network bridges"
	@echo ""

# Environment Management
start:
	@echo "$(BLUE)Starting RAS environment...$(NC)"
	cd $(RAS_DIR) && ./ras.sh $(SCENARIO) start

stop:
	@echo "$(YELLOW)Stopping RAS environment...$(NC)"
	cd $(RAS_DIR) && ./ras.sh $(SCENARIO) stop

restart:
	@echo "$(BLUE)Restarting RAS environment...$(NC)"
	cd $(RAS_DIR) && ./ras.sh $(SCENARIO) restart

clean:
	@echo "$(RED)Cleaning RAS environment...$(NC)"
	cd $(RAS_DIR) && ./ras.sh $(SCENARIO) clean

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
