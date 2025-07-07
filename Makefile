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
	@echo "  apply-netem    - Apply network conditions"
	@echo "  reset-netem    - Reset network conditions"
	@echo "  label          - Label captured traffic"
	@echo ""
	@echo "Available scenarios:"
	@echo "  SCENARIO=low-and-slow-sqli    - SQL injection attack scenario"
	@echo "  SCENARIO=ssh-tunnel-lateral   - SSH tunnel lateral movement"
	@echo "  SCENARIO=https-c2-backdoor    - HTTPS C2 backdoor scenario"
	@echo ""
	@echo "Scenario-specific targets:"
	@echo "  sqli-up        - Start SQL injection scenario"
	@echo "  sqli-attack    - Run SQL injection attack"
	@echo "  sqli-benign    - Run SQL injection benign traffic"
	@echo "  ssh-up         - Start SSH tunnel scenario"
	@echo "  ssh-attack     - Run SSH tunnel attack"
	@echo "  https-up       - Start HTTPS C2 scenario"
	@echo "  https-attack   - Run HTTPS C2 attack"
	@echo ""
	@echo "Usage examples:"
	@echo "  make build && make sqli-up && make apply-netem && make sqli-benign && make sqli-attack"
	@echo "  make build && make ssh-up && make ssh-attack"
	@echo "  make build && make https-up && make https-attack"

# Build all Docker images
build:
	@echo "Building Docker images..."
	docker build -t securitylogs-webapp containers/webapp
	docker build -t securitylogs-attacker containers/attacker
	docker build -t securitylogs-tcpdump containers/tcpdump
	docker build -t securitylogs-victim containers/victim
	docker build -t securitylogs-c2-server containers/c2-server
	docker build -t securitylogs-backend-api containers/backend-api
	@echo "Build completed!"

# Clean up containers and images
clean:
	@echo "Cleaning up containers and images..."
	docker-compose -f scenarios/*/docker-compose.yml down --remove-orphans
	docker rmi securitylogs-webapp securitylogs-attacker securitylogs-tcpdump securitylogs-victim securitylogs-c2-server securitylogs-backend-api 2>/dev/null || true
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
	bash control/apply_netem.sh

reset-netem:
	@echo "Resetting network conditions..."
	bash control/reset_netem.sh

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
	docker exec securitylogs-webapp bash /opt/scripts/run_benign.sh

sqli-capture:
	@echo "Running complete SQL injection capture..."
	cd scenarios/low-and-slow-sqli && bash capture.sh

# Generic attack and benign targets
attack:
	@echo "Running attack scenario..."
	@if [ -f "scenarios/low-and-slow-sqli/run_attack.sh" ]; then \
		docker exec securitylogs-attacker bash /opt/scripts/run_attack.sh; \
	else \
		echo "No attack script found"; \
	fi

benign:
	@echo "Running benign traffic simulation..."
	@if [ -f "scenarios/low-and-slow-sqli/run_benign.sh" ]; then \
		docker exec securitylogs-webapp bash /opt/scripts/run_benign.sh; \
	else \
		echo "No benign script found"; \
	fi

# Traffic labeling
label:
	@echo "Labeling captured traffic..."
	python3 utils/label_pcap.py pcap_data/low-and-slow-sqli logs/labels.csv

# Quick start for SQL injection scenario
sqli-quick: build sqli-up apply-netem sqli-benign sqli-attack label
	@echo "SQL injection scenario completed!"

# SSH Tunnel scenario targets
ssh-up:
	@echo "Starting SSH tunnel scenario..."
	cd scenarios/ssh-tunnel-lateral && docker-compose up -d

ssh-down:
	@echo "Stopping SSH tunnel scenario..."
	cd scenarios/ssh-tunnel-lateral && docker-compose down

ssh-attack:
	@echo "Running SSH tunnel attack..."
	docker exec securitylogs-ssh-attacker bash /opt/scripts/run_ssh_attack.sh

ssh-quick: build ssh-up apply-netem ssh-attack
	@echo "SSH tunnel scenario completed!"

# HTTPS C2 scenario targets
https-up:
	@echo "Starting HTTPS C2 scenario..."
	cd scenarios/https-c2-backdoor && docker-compose up -d

https-down:
	@echo "Stopping HTTPS C2 scenario..."
	cd scenarios/https-c2-backdoor && docker-compose down

https-attack:
	@echo "Running HTTPS C2 attack..."
	docker exec securitylogs-backend-api node /app/src/malicious_module.js

https-quick: build https-up apply-netem https-attack
	@echo "HTTPS C2 scenario completed!"

# Show logs
logs:
	@echo "Showing container logs..."
	docker-compose -f scenarios/low-and-slow-sqli/docker-compose.yml logs -f

# Show status
status:
	@echo "Container status:"
	docker-compose -f scenarios/low-and-slow-sqli/docker-compose.yml ps
