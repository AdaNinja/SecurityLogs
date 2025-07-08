# Security Logs Attack Scenarios

This repository contains a collection of containerised attack scenarios used for generating security log datasets. Each scenario provides Docker configurations and helper scripts to reproduce specific network intrusions in a controlled environment.

## Project Structure

```
.
├── containers/            # Docker images used across scenarios
├── control/               # Network emulation helpers
├── scenarios/             # Individual attack scenarios
├── utils/                 # Traffic processing scripts
├── Makefile               # Helper commands
└── README.md
```

## Available Scenarios

- **low-and-slow-sqli** – Simulates a slow SQL injection attack with background web traffic.
- **https-c2-backdoor** – Demonstrates a malicious HTTPS command-and-control backdoor.
- **ssh-tunnel-lateral** – Shows lateral movement using an SSH tunnel.

## Usage

1. Build all Docker images:
   ```bash
   make build
   ```
2. Run a scenario. Example for the SQL injection scenario:
   ```bash
   make sqli-quick
   ```
   For other scenarios, use `make https-quick` or `make ssh-quick`.
3. When finished, stop and remove containers:
   ```bash
   make clean
   ```

Logs and PCAP files will be written to the `logs/` and `pcap_data/` directories under each scenario.

## Security Considerations

⚠️ **Important Reminder**
- These scenarios are for research and education purposes only.
- Run them in an isolated test environment.
- Do not use on production systems or real networks.
- Always comply with local laws and regulations.

## Contributing

Contributions and issues are welcome. Feel free to open a PR to improve the scenarios or documentation.
