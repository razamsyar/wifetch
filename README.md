# WiFetch

**Cross-platform WiFi Credential Recovery**

A specialized penetration testing tool for authorized security assessments. WiFetch enables security professionals to extract saved WiFi credentials during the **Credential Access** phase of MITRE ATT&CK (T1555 - Credentials from Password Stores).

*P.S. - Also handy for when you forget your own WiFi password!*

## Features

- **Cross-platform credential extraction** (Windows, Linux, macOS)
- **Multiple export formats** (TXT, JSON, CSV, XML)
- **Search capabilities** for specific networks

## Requirements

- **Python**: 3.7+ (preferably latest)
- **Privileges**: Administrator/sudo access required
- **Authorization**: Valid penetration testing engagement scope
- **Environment**: Controlled testing environment with expected detection

## Installation

```bash
git clone https://github.com/razamsyar/wifetch.git
cd wifetch
```

## Usage

```bash
# List all WiFi passwords
python3 wifetch.py

# Quiet mode (minimal output)
python3 wifetch.py -q

# Search for specific network
python3 wifetch.py -s Home

# Export to text file (default)
python3 wifetch.py -e wifipass.txt

# Export to JSON format
python3 wifetch.py -e wifipass.json -f json

# Export to CSV format
python3 wifetch.py -e wifipass.csv -f csv

# Export to XML format
python3 wifetch.py -e wifipass.xml -f xml

# Search and export as JSON
python3 wifetch.py -s Home -e wifipass.json -f json
```

## License

MIT License

## Legal Disclaimer

**AUTHORIZED USE ONLY**: This tool is designed for authorized penetration testing and security assessments. Users must have explicit written authorization before using this tool. Unauthorized use is strictly prohibited and may violate local, state, and federal laws. Users are solely responsible for ensuring compliance with applicable laws and regulations.