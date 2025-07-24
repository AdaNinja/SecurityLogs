# SecurityLogs Project Makefile
# Simplified management for attack scenarios

.PHONY: help build build-clean clean up down run-variant run-all-variants run-variants logs status validate-data show-data variant-complete all netem netem-apply netem-reset check-images

# Default scenario
SCENARIO ?= low-and-slow-sqli

# Default target
help:
	@echo "SecurityLogs - Attack Scenario Management"
	@echo ""
	@echo "QUICK START (Fully Automated):"
	@echo "  make all                    # Complete workflow: build + run all variants + validate"
	@echo "  make variant-complete VARIANT=stealthy  # Single variant complete workflow"
	@echo ""
	@echo "CORE COMMANDS:"
	@echo "  build              - Build all Docker images (with host network)"
	@echo "  build-clean        - Clean cache and rebuild (fixes network issues)"
	@echo "  clean              - Clean up containers and images"
	@echo "  clean-data         - Clean up all experiment data (logs, pcaps, processed)"
	@echo "  clean-all          - Clean up everything (containers, images, and data)"
	@echo "  up/down            - Start/stop containers"
	@echo ""
	@echo "EXPERIMENT COMMANDS:"
	@echo "  run-variant        - Run single variant (with ETL processing)"
	@echo "  run-all-variants   - Run all variants (with ETL processing)"
	@echo "  run-variants       - Run specific variants (VARIANTS='stealthy moderate')"
	@echo ""
	@echo "DATA COMMANDS:"
	@echo "  validate-data      - Validate generated datasets"
	@echo "  show-data          - Show extracted data summary"
	@echo ""
	@echo "MONITORING:"
	@echo "  logs               - Show container logs"
	@echo "  status             - Show container status"
	@echo ""
	@echo "EXAMPLES:"
	@echo "  make all                                    # Complete automated workflow"
	@echo "  make variant-complete VARIANT=stealthy     # Single variant workflow"
	@echo "  make run-variant VARIANT=moderate          # Run specific variant"
	@echo "  make validate-data                         # Check data quality"

# Check if Docker images exist
check-images:
	@echo "Checking Docker images..."
	@if ! docker images | grep -q "securitylogs-webapp"; then \
		echo "Image securitylogs-webapp not found, will build"; \
		exit 1; \
	fi
	@if ! docker images | grep -q "securitylogs-attacker"; then \
		echo "Image securitylogs-attacker not found, will build"; \
		exit 1; \
	fi
	@if ! docker images | grep -q "securitylogs-tcpdump"; then \
		echo "Image securitylogs-tcpdump not found, will build"; \
		exit 1; \
	fi
	@if ! docker images | grep -q "securitylogs-dns-server"; then \
		echo "Image securitylogs-dns-server not found, will build"; \
		exit 1; \
	fi
	@echo "All Docker images found, skipping build"

# Build all Docker images (only if needed)
build: check-images
	@echo "Building Docker images with host network..."
	docker build --network=host -t securitylogs-webapp containers/webapp
	docker build --network=host -t securitylogs-attacker containers/attacker
	docker build --network=host -t securitylogs-tcpdump containers/tcpdump
	docker build --network=host -t securitylogs-dns-server containers/dns-server
	@echo "Build completed!"

# Force rebuild all Docker images (clean cache)
build-clean:
	@echo "Cleaning Docker cache and building images..."
	docker system prune -a -f
	docker builder prune -a -f
	@echo "Cache cleaned, building images with host network..."
	docker build --network=host -t securitylogs-webapp containers/webapp
	docker build --network=host -t securitylogs-attacker containers/attacker
	docker build --network=host -t securitylogs-tcpdump containers/tcpdump
	docker build --network=host -t securitylogs-dns-server containers/dns-server
	@echo "Build completed!"

# Clean up containers and images
clean:
	@echo "Cleaning up containers and images..."
	docker-compose -f scenarios/*/docker-compose.yml down --remove-orphans
	docker rmi securitylogs-webapp securitylogs-attacker securitylogs-tcpdump securitylogs-dns-server 2>/dev/null || true
	@echo "Cleanup completed!"

# Clean up all data (logs, pcaps, processed data)
clean-data:
	@echo "Cleaning up all experiment data..."
	@echo "Removing logs..."
	rm -rf data/logs/*
	@echo "Removing PCAP files..."
	rm -rf data/pcaps/*
	@echo "Removing DNS logs..."
	rm -rf data/dns_logs/*
	@echo "Removing processed data..."
	rm -rf data/processed/*
	@echo "Data cleanup completed!"

# Clean up everything (containers, images, and data)
clean-all: clean clean-data
	@echo "Complete cleanup finished!"

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
netem-apply:
	@echo "Applying network conditions..."
	bash scripts/network/apply_netem.sh

netem-reset:
	@echo "Resetting network conditions..."
	bash scripts/network/reset_netem.sh

netem: netem-apply
	@echo "Network conditions applied"

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

# Traffic labeling (legacy - removed log-aggregator)
label:
	@echo "Labeling captured traffic..."
	@echo "Note: log-aggregator has been removed. Use ETL scripts for data processing."

# Data validation and verification
validate-data:
	@echo "Validating generated datasets..."
	@echo "Checking for unified datasets..."
	@for variant in stealthy moderate aggressive; do \
		if [ -f "data/processed/lowscan_$${variant}/unified/unified_dataset.csv" ]; then \
			echo "[OK] Unified dataset found for $$variant"; \
		else \
			echo "[MISSING] Unified dataset missing for $$variant"; \
		fi; \
		if [ -f "data/processed/lowscan_$${variant}/unified/simplified_view.csv" ]; then \
			echo "[OK] Simplified view found for $$variant"; \
		else \
			echo "[MISSING] Simplified view missing for $$variant"; \
		fi; \
	done

show-data:
	@echo "Showing extracted data summary..."
	python3 scripts/show_extracted_data.py --summary

# Complete attack workflow (fully automated)
all: build run-all-variants validate-data
	@echo "Complete attack workflow finished!"
	@echo "All variants executed with ETL processing"
	@echo "Check data/processed/ for results"

# Single variant complete workflow
variant-complete: build run-variant validate-data
	@echo "Single variant workflow completed!"
	@echo "Variant $(VARIANT) executed with ETL processing"

# Quick start for SQL injection scenario
sqli-quick: build up run-variant VARIANT=stealthy
	@echo "SQL injection scenario completed!"

# Show logs
logs:
	@echo "Showing container logs..."
	docker-compose -f scenarios/low-and-slow-sqli/docker-compose.yml logs -f

# Show status
status:
	@echo "Container status:"
	docker-compose -f scenarios/low-and-slow-sqli/docker-compose.yml ps
