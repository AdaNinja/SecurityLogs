# Phishing Attack Scenario (Scenario 1)

## Scenario Description
This scenario simulates a typical phishing attack process where attackers send phishing emails to induce users to click malicious links, triggering a series of malicious behaviors.

## Attack Process
1. Attacker sends phishing email to target user
2. User clicks malicious link in the email
3. Malicious link triggers download and execution of malicious program
4. Malicious program establishes persistence in the system
5. Attacker gains system control

## File Description
- `config.json`: Scenario configuration file, containing attack parameters and configuration
- `attack.py`: Attack simulation script
- `data/`: Directory for scenario-related data files
  - `raw/`: Raw log data
  - `processed/`: Processed data

## Data Collection
This scenario collects data of the following types:
- Windows security logs
- Sysmon logs
- Network traffic data (PCAP)
- System behavior data

## Tag Description
- L1: Phishing email sending and clicking
- L2: Malicious program download and execution
- L3: System persistence
- L4: Attacker control