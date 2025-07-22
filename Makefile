# SecurityLogs Project Makefile
# Simplified management for attack scenarios

.PHONY: help build clean up down run-variant run-all-variants run-variants logs status

# Default scenario
SCENARIO ?= low-and-slow-sqli

# Default target
help:
	@echo "SecurityLogs - Attack Scenario Management"
	@echo ""
	@echo "Quick Start:"
	@echo "  make build              # Build Docker images"
	@echo "  make run-all-variants   # Run all variants (with interleaved traffic)"
	@echo "  make run-variant VARIANT=stealthy  # Run single variant"
	@echo ""
	@echo "Core Commands:"
	@echo "  build          - Build all Docker images (with host network)"
	@echo "  build-clean    - Clean cache and rebuild (fixes network issues)"
	@echo "  clean          - Clean up containers and images"
	@echo "  up/down        - Start/stop containers"
	@echo "  run-variant    - Run single variant (with interleaved traffic & network conditions)"
	@echo "  run-all-variants - Run all variants (with interleaved traffic & network conditions)"
	@echo "  run-variants   - Run specific variants (VARIANTS='stealthy moderate')"
	@echo ""
	@echo "Monitoring:"
	@echo "  logs           - Show container logs"
	@echo "  status         - Show container status"
	@echo ""
	@echo "Examples:"
	@echo "  make build && make run-all-variants"
	@echo "  make run-variant VARIANT=stealthy"
	@echo "  make build-clean  # If network issues occur"

# Build all Docker images
build:
	@echo "Building Docker images with host network..."
	docker build --network=host -t securitylogs-webapp containers/webapp
	docker build --network=host -t securitylogs-attacker containers/attacker
	docker build --network=host -t securitylogs-tcpdump containers/tcpdump
	@echo "Build completed!"

# Clean cache and build all Docker images
build-clean:
	@echo "Cleaning Docker cache and building images..."
	docker system prune -a -f
	docker builder prune -a -f
	@echo "Cache cleaned, building images with host network..."
	docker build --network=host -t securitylogs-webapp containers/webapp
	docker build --network=host -t securitylogs-attacker containers/attacker
	docker build --network=host -t securitylogs-tcpdump containers/tcpdump
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

# Network condition management (automatically applied)
apply-netem:
	@echo "Applying network conditions..."
	bash scripts/network/apply_netem.sh

reset-netem:
	@echo "Resetting network conditions..."
	bash scripts/network/reset_netem.sh

# Automated variant runners (with interleaved traffic and network conditions by default)
run-variant:
	@echo "Running variant with interleaved traffic and network conditions..."
	@if [ -z "$(VARIANT)" ]; then \
		echo "Error: VARIANT not specified. Use: make run-variant VARIANT=stealthy"; \
		exit 1; \
	fi
	@echo "Applying network conditions..."
	@sudo bash scripts/network/apply_netem.sh
	@echo "Running variant with interleaved traffic..."
	python3 scripts/run_variant.py $(VARIANT) --interleaved $(if $(BENIGN_MIX),--benign-mix $(BENIGN_MIX)) $(if $(BENIGN_DURATION),--benign-duration $(BENIGN_DURATION))
	@echo "Resetting network conditions..."
	@sudo bash scripts/network/reset_netem.sh

run-all-variants:
	@echo "Running all variants with interleaved traffic and network conditions..."
	@echo "Applying network conditions..."
	@sudo bash scripts/network/apply_netem.sh
	@echo "Running all variants with interleaved traffic..."
	python3 scripts/run_all_variants.py --interleaved $(if $(BENIGN_MIX),--benign-mix $(BENIGN_MIX)) $(if $(BENIGN_DURATION),--benign-duration $(BENIGN_DURATION))
	@echo "Resetting network conditions..."
	@sudo bash scripts/network/reset_netem.sh

run-variants:
	@echo "Running specific variants with interleaved traffic and network conditions..."
	@if [ -z "$(VARIANTS)" ]; then \
		echo "Error: VARIANTS not specified. Use: make run-variants VARIANTS='stealthy moderate'"; \
		exit 1; \
	fi
	@echo "Applying network conditions..."
	@sudo bash scripts/network/apply_netem.sh
	@echo "Running variants with interleaved traffic..."
	python3 scripts/run_all_variants.py --variants $(VARIANTS) --interleaved $(if $(BENIGN_MIX),--benign-mix $(BENIGN_MIX)) $(if $(BENIGN_DURATION),--benign-duration $(BENIGN_DURATION))
	@echo "Resetting network conditions..."
	@sudo bash scripts/network/reset_netem.sh

# Legacy commands (for backward compatibility)
attack:
	@echo "Running basic SQL injection attack (legacy)..."
	cd scenarios/low-and-slow-sqli && docker exec securitylogs-attacker python3 /opt/scripts/attack_modules/container_attack.py

attack-stealthy:
	@echo "Running stealthy attack variant (legacy)..."
	cd scenarios/low-and-slow-sqli && docker exec securitylogs-attacker python3 /opt/scripts/attack_modules/container_attack.py --risk 1 --level 1

attack-moderate:
	@echo "Running moderate attack variant (legacy)..."
	cd scenarios/low-and-slow-sqli && docker exec securitylogs-attacker python3 /opt/scripts/attack_modules/container_attack.py --risk 1 --level 2

attack-aggressive:
	@echo "Running aggressive attack variant (legacy)..."
	cd scenarios/low-and-slow-sqli && docker exec securitylogs-attacker python3 /opt/scripts/attack_modules/container_attack.py --risk 2 --level 3

# Legacy interleaved command (for backward compatibility)
interleaved:
	@echo "Running interleaved attack (legacy)..."
	bash scripts/attack/interleaved_attack.sh $(ARGS)

# Benign traffic simulation (legacy)
benign:
	@echo "Running benign traffic simulation (legacy)..."
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

# Complete attack workflow (simplified)
all: build up run-all-variants collect-logs analyze report
	@echo "Complete attack workflow finished!"

# Quick start for SQL injection scenario
sqli-quick: build up run-variant VARIANT=stealthy label
	@echo "SQL injection scenario completed!"

# Show logs
logs:
	@echo "Showing container logs..."
	docker-compose -f scenarios/low-and-slow-sqli/docker-compose.yml logs -f

# Show status
status:
	@echo "Container status:"
	docker-compose -f scenarios/low-and-slow-sqli/docker-compose.yml ps
