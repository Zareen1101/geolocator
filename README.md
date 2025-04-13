# 🌐 IP Geolocation & Security Scanner

*A comprehensive network analysis tool* that captures traffic, maps IP locations, and scans for vulnerabilities.

## ✨ Features

| Feature | Description |
|---------|-------------|
| 📡 Traffic Capture | Uses Wireshark's tshark to capture live network traffic |
| 🌍 IP Geolocation | Maps IP addresses to physical locations using ipinfo.io |
| 🔍 Vulnerability Scanning | Checks for known vulnerabilities using Shodan API |
| 🗺 Interactive Visualization | Creates Folium maps with color-coded security status |
| 📊 Smart Reporting | Generates detailed security assessment reports |
| 💾 Data Export | Saves all results to CSV for further analysis |

## 🛠 Installation

### Prerequisites
- Python 3.6+
- Wireshark installed (with tshark in PATH)
- API keys:
  - [Free ipinfo.io token](https://ipinfo.io/)
  - [Free Shodan API key](https://developer.shodan.io/)

### Setup
```bash
# Clone repository
git clone https://github.com/yourusername/ip-security-scanner.git
cd ip-security-scanner

# Install dependencies
pip install -r requirements.txt

## ⚙ Configuration

Edit the configuration section in ip_security_tracker.py:

```python
# API Configuration
IPINFO_TOKEN = "your_ipinfo_token_here"  # Free tier: 50k requests/month
SHODAN_API_KEY = "your_shodan_key_here"  # Free tier: 100 scans/month

# Path Configuration
TSHARK_PATH = r"C:\Path\To\tshark.exe"  # Typical paths:
                                        # Windows: C:\Program Files\Wireshark\tshark.exe
                                        # Linux/Mac: /usr/bin/tshark

# Network Configuration
INTERFACE = "Wi-Fi"  # Common options: "Ethernet", "eth0", "en0"
