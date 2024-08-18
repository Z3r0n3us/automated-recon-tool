# Automated Reconnaissance Tool

## Overview

This tool automates the reconnaissance phase of penetration testing by performing tasks such as subdomain enumeration, port scanning, and vulnerability detection.

## Installation

1. **Clone the Repository**:
   ```
   git clone https://github.com/your-username/automated-recon-tool.git
   cd automated-recon-tool
   ```

2. **Setup the Environment**:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. **Install Dependencies**:
   ```
   pip install -r requirements.txt
   ```

4. **Configure API Keys**:
   ```
   Add your API keys to config/api_keys.json.
   ```

## Usage

```
python recon_tool.py --target example.com --output report.txt
```

## Features

### Command-Line Arguments:

--target: Specifies the target domain or IP address.
--ports: Allows selection of the port range to scan (common, extended, all, or custom).
--custom-ports: Allows specifying a custom list of ports if --ports is set to custom.
--output: (Optional) Specify an output file for results (not yet implemented in this script but can be added).


API Key Management:

Loads API keys from a config/api_keys.json file.
Subdomain Enumeration:

Uses dnspython to perform DNS resolution and find subdomains.
Port Scanning:

Integrates with nmap using the python-nmap library to scan for open ports based on the selected port range.
Vulnerability Detection:

Uses the Shodan API to check for known vulnerabilities associated with the target’s IP address.
Port Range Options:

common: Scans ports 1-1024.
extended: Scans ports 1-12000.
all: Scans all ports 0-65535.
custom: Allows specifying a custom range or list of ports.


## Examples

Scan Common Ports (1-1024):
```
python recon_tool.py --target example.com --ports common
```

Scan Extended Ports (1-12000):
```
python recon_tool.py --target example.com --ports extended
```

Scan All Ports (0-65535):
```
python recon_tool.py --target example.com --ports all
```

Scan Custom Ports:
```
python recon_tool.py --target example.com --ports custom --custom-ports 80,443,8080
```