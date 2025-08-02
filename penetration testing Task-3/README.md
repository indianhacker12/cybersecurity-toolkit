# Penetration Testing Toolkit

A comprehensive Python-based penetration testing toolkit for network security assessment and vulnerability scanning.

⚠️ **IMPORTANT: This tool is for educational purposes and authorized testing only. Do not use it against systems without explicit permission.**

## Features

1. **Port Scanner**
   - Multi-threaded port scanning
   - Common ports detection
   - Banner grabbing
   - Customizable port ranges

2. **Service Detection**
   - Identifies running services
   - Banner analysis
   - Common service fingerprinting

3. **SSH Brute Force**
   - Password testing
   - Multiple username support
   - Rate limiting to avoid detection
   - Customizable wordlists

4. **FTP Brute Force**
   - Anonymous login testing
   - Multiple credential combinations
   - Connection timeout handling

5. **Web Directory Scanner**
   - Common directory enumeration
   - Status code reporting
   - Detection of hidden paths
   - Support for custom wordlists

6. **Vulnerability Scanner**
   - SMB share enumeration
   - SSL/TLS version checking
   - Web server version detection
   - Basic security misconfigurations

7. **Network Discovery**
   - Host discovery
   - Multi-threaded scanning
   - ICMP echo scanning
   - Range-based scanning

8. **Comprehensive Scanning**
   - Combined module execution
   - Automated report generation
   - Service correlation

## Requirements

- Python 3.x
- Required packages:
  - paramiko (SSH)
  - requests
  - ftplib
  - socket
  - subprocess
  - threading
  - concurrent.futures

## Installation

1. Clone this repository
2. Install required dependencies:
```bash
pip install paramiko requests
```

## Usage

Run the script:
```bash
python main.py
```

Choose from the following options:
1. Port Scanner
2. Service Detection
3. SSH Brute Force
4. FTP Brute Force
5. Web Directory Scanner
6. Vulnerability Scanner
7. Network Discovery
8. Full Scan (All modules)
9. Exit

## Security Notice

This toolkit is designed for:
- Educational purposes
- Authorized penetration testing
- Security research
- System administration

**DO NOT USE** this tool against:
- Unauthorized systems
- Production environments without permission
- Critical infrastructure
- Systems you don't own or have explicit permission to test

## Legal Disclaimer

Usage of this toolkit for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

## License

This project is for educational purposes only. Use at your own risk.
