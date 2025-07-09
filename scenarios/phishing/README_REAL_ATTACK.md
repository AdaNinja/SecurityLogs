# Real Phishing Attack Implementation

## Overview

This phishing attack scenario has been enhanced to execute **real attacks** rather than simulations. The system now:

1. **Installs required services automatically** (MailHog, credential collector)
2. **Sends real phishing emails** via MailHog
3. **Executes real browser interactions** (opening emails, clicking links)
4. **Performs real credential theft** via form submission
5. **Verifies attack success** through multiple checks

## Key Improvements

### 1. Service Installation in scenario.yaml

The `scenario.yaml` now includes service configuration:

```yaml
services:
  mailhog:
    install: true
    version: "v1.0.1"
    download_url: "https://github.com/mailhog/MailHog/releases/download/v1.0.1/MailHog_linux_amd64"
    ports:
      smtp: 1025
      web_ui: 8025
    auto_start: true
  
  credential_collector:
    install: true
    port: 9000
    auto_start: true
```

### 2. Real Attack Execution Settings

```yaml
attack_execution:
  real_email_sending: true
  real_browser_interaction: true
  real_form_submission: true
  real_credential_collection: true
  verification_checks: true
```

### 3. Enhanced Browser Configuration

```yaml
browser:
  headless: false  # Real browser window for interaction
  timeout: 30
  user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  window_size: "1920x1080"
```

## Attack Flow

### Step 0: Service Installation
- **MailHog**: Downloads and installs MailHog email testing tool
- **Credential Collector**: Starts Flask server for credential capture
- **Verification**: Checks all services are running

### Step 1: Real Email Sending
- Sends actual phishing email via MailHog SMTP
- Email contains real phishing link
- Logs email delivery with metadata

### Step 2: Real Email Interaction
- Opens real browser window (non-headless)
- Accesses MailHog web interface
- Clicks on actual phishing email
- Clicks real phishing link in email
- Opens phishing page in new window

### Step 3: Real Credential Theft
- Fills phishing form with realistic credentials
- Submits form to credential collection server
- Verifies credentials were captured
- Logs successful credential theft

## Files Structure

```
scenarios/phishing/
├── scenario.yaml              # Enhanced configuration
├── attack.py                  # Real attack implementation
├── service_installer.py       # Service installation
├── credential_collector.py    # Credential collection server
├── labels.py                  # Attack labels
└── README_REAL_ATTACK.md      # This file
```

## Usage

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run Attack

```bash
python run_scenario.py phishing
```

### 3. Monitor Services

- **MailHog Web UI**: http://localhost:8025
- **Credential Collector**: http://localhost:9000
- **Phishing Page**: http://localhost:9000/phish

## Verification Points

### Email Verification
- Check MailHog web interface for sent emails
- Verify email content and links

### Browser Interaction Verification
- Watch real browser window open
- Observe email opening and link clicking
- Verify phishing page loads

### Credential Collection Verification
- Check `/credentials` endpoint for captured data
- Verify form submission logs
- Confirm credential theft success

## Security Considerations

⚠️ **Important**: This is a real attack implementation for educational/research purposes only.

1. **Isolated Environment**: Run only in controlled, isolated environments
2. **No Real Targets**: Never target real users or systems
3. **Data Protection**: Captured credentials are stored in memory only
4. **Cleanup**: Services are automatically cleaned up after execution

## Troubleshooting

### MailHog Issues
```bash
# Check if MailHog is running
ps aux | grep mailhog

# Restart MailHog
pkill mailhog
mailhog -api-bind-addr 0.0.0.0:8025 -ui-bind-addr 0.0.0.0:8025 -smtp-bind-addr 0.0.0.0:1025
```

### Credential Collector Issues
```bash
# Check if server is running
curl http://localhost:9000/health

# View collected credentials
curl http://localhost:9000/credentials
```

### Browser Issues
- Ensure Firefox is installed
- Check if geckodriver is in PATH
- Verify display settings for non-headless mode

## Logging

All attack events are logged with detailed metadata:

```json
{
  "event": "phishing_email_sent",
  "timestamp": "2024-01-01T12:00:00Z",
  "data": {
    "subject": "Important Notice: Your Account Needs Verification",
    "target": "victim@company.com",
    "real_email": true
  }
}
```

## Success Metrics

The attack is considered successful when:

1. ✅ MailHog service is running
2. ✅ Phishing email is sent successfully
3. ✅ Email is opened in browser
4. ✅ Phishing link is clicked
5. ✅ Phishing page loads correctly
6. ✅ Form is filled and submitted
7. ✅ Credentials are captured and verified

This implementation ensures that every step of the phishing attack chain is **real and verifiable**, providing authentic data for security analysis and research. 