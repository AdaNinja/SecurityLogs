# SecurityLogs Project Makefile
# Unified management for all attack scenarios

.PHONY: help build clean up down benign attack netem apply reset label

# Default scenario
SCENARIO ?= low-and-slow-sqli

# Default target
help:
	@echo "SecurityLogs - Attack Scenario Management"
	@echo ""
	@echo "Available targets:"
	@echo "  build          - Build all Docker images"
	@echo "  clean          - Clean up containers and images"
	@echo "  up             - Start containers for current scenario"
	@echo "  down           - Stop and remove containers"
	@echo "  benign         - Run benign traffic simulation"
	@echo "  attack         - Run attack scenario"
	@echo "  attack-stealthy - Run stealthy attack variant"
	@echo "  attack-moderate - Run moderate attack variant"
	@echo "  attack-aggressive - Run aggressive attack variant"
	@echo "  interleaved    - Run interleaved attack with benign traffic"
	@echo "  apply-netem    - Apply network conditions"
	@echo "  reset-netem    - Reset network conditions"
	@echo "  label          - Label captured traffic"
	@echo "  collect-logs   - Collect all logs and PCAP files"
	@echo "  analyze        - Analyze collected data"
	@echo "  report         - Generate analysis report"
	@echo "  all            - Complete attack workflow"
	@echo ""
	@echo "Available scenarios:"
	@echo "  SCENARIO=low-and-slow-sqli    - SQL injection attack scenario"
	@echo ""
	@echo "Scenario-specific targets:"
	@echo "  sqli-up        - Start SQL injection scenario"
	@echo "  sqli-attack    - Run SQL injection attack"
	@echo "  sqli-benign    - Run SQL injection benign traffic"
	@echo ""
	@echo "Usage examples:"
	@echo "  make build && make up && make apply-netem && make benign && make attack"
	@echo "  make all                    # Complete workflow"
	@echo "  make interleaved           # Interleaved attack with benign traffic"
	@echo "  make interleaved ARGS='--attack-variants stealthy,aggressive'"
	@echo "  make interleaved ARGS='--benign-mix HTTP:0.8,DNS:0.2 --attack-delay 10-20'"
	@echo "  make attack-stealthy       # Stealthy attack variant"
	@echo "  make attack-moderate       # Moderate attack variant"
	@echo "  make attack-aggressive     # Aggressive attack variant"

# Build all Docker images
build:
	@echo "Building Docker images..."
	docker build -t securitylogs-webapp containers/webapp
	docker build -t securitylogs-attacker containers/attacker
	docker build -t securitylogs-tcpdump containers/tcpdump
	@echo "Build completed!"

# Clean up containers and images
clean:
	@echo "Cleaning up containers and images..."
	docker-compose -f scenarios/*/docker-compose.yml down --remove-orphans
	docker rmi securitylogs-webapp securitylogs-attacker securitylogs-tcpdump 2>/dev/null || true
	@echo "Cleanup completed!"

# Generic container management
up:
	@echo "Starting containers..."
	@if [ -f "scenarios/low-and-slow-sqli/docker-compose.yml" ]; then \
		cd scenarios/low-and-slow-sqli && docker-compose up -d; \
	else \
		echo "No docker-compose.yml found in current scenario"; \
	fi

down:
	@echo "Stopping containers..."
	@if [ -f "scenarios/low-and-slow-sqli/docker-compose.yml" ]; then \
		cd scenarios/low-and-slow-sqli && docker-compose down; \
	else \
		echo "No docker-compose.yml found in current scenario"; \
	fi

# Network condition management
apply-netem:
	@echo "Applying network conditions..."
	bash control/network/apply_netem.sh

reset-netem:
	@echo "Resetting network conditions..."
	bash control/network/reset_netem.sh

# SQL Injection scenario targets
sqli-up:
	@echo "Starting SQL injection scenario..."
	cd scenarios/low-and-slow-sqli && docker-compose up -d

sqli-down:
	@echo "Stopping SQL injection scenario..."
	cd scenarios/low-and-slow-sqli && docker-compose down

sqli-attack:
	@echo "Running SQL injection attack..."
	docker exec securitylogs-attacker bash /opt/scripts/run_attack.sh

sqli-benign:
	@echo "Running SQL injection benign traffic..."
	docker exec securitylogs-webapp bash /opt/scripts/benign_modules/run_benign.sh

sqli-capture:
	@echo "Running complete SQL injection capture..."
	cd scenarios/low-and-slow-sqli && bash capture.sh

# Attack variants
attack:
	@echo "Running basic SQL injection attack..."
	cd scenarios/low-and-slow-sqli && docker exec securitylogs-attacker python3 /opt/scripts/container_attack.py

attack-stealthy:
	@echo "Running stealthy attack variant (RISK=1, LEVEL=1)..."
	cd scenarios/low-and-slow-sqli && docker exec securitylogs-attacker python3 /opt/scripts/container_attack.py --risk 1 --level 1

attack-moderate:
	@echo "Running moderate attack variant (RISK=1, LEVEL=2)..."
	cd scenarios/low-and-slow-sqli && docker exec securitylogs-attacker python3 /opt/scripts/container_attack.py --risk 1 --level 2

attack-aggressive:
	@echo "Running aggressive attack variant (RISK=2, LEVEL=3)..."
	cd scenarios/low-and-slow-sqli && docker exec securitylogs-attacker python3 /opt/scripts/container_attack.py --risk 2 --level 3

# Interleaved attack with benign traffic
interleaved:
	@echo "Running interleaved attack with benign traffic..."
	cd scenarios/low-and-slow-sqli && bash ../../control/automation/run_all_variants.sh $(ARGS)

# Benign traffic simulation
benign:
	@echo "Running benign traffic simulation..."
	cd scenarios/low-and-slow-sqli && docker exec securitylogs-webapp bash /opt/scripts/benign_modules/run_benign.sh

# Traffic labeling
label:
	@echo "Labeling captured traffic..."
	cd scenarios/low-and-slow-sqli && python3 ../../control/automation/multi_source_logger.py

# Data collection and analysis
collect-logs:
	@echo "Collecting all logs and PCAP files..."
	cd scenarios/low-and-slow-sqli && make collect-logs

analyze:
	@echo "Analyzing collected data..."
	cd scenarios/low-and-slow-sqli && make analyze

report:
	@echo "Generating analysis report..."
	cd scenarios/low-and-slow-sqli && make report

# Complete attack workflow
all: build up apply-netem interleaved collect-logs analyze report
	@echo "Complete attack workflow finished!"

# Quick start for SQL injection scenario
sqli-quick: build sqli-up apply-netem sqli-benign sqli-attack label
	@echo "SQL injection scenario completed!"



# Show logs
logs:
	@echo "Showing container logs..."
	docker-compose -f scenarios/low-and-slow-sqli/docker-compose.yml logs -f

# Show status
status:
	@echo "Container status:"
	docker-compose -f scenarios/low-and-slow-sqli/docker-compose.yml ps
