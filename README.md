# 🌐 IP Geolocation Tracker

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

---

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
```
---

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
```
## Usage
```python
python gelocation_tracker.py
```

---

# 🔐 IP Security Scanner

## 📂 Output Files

| File Name               | Description                                           |
|------------------------|-------------------------------------------------------|
| security_scan_results.csv | Complete scan data (IPs, locations, vulnerabilities) |
| ip_map.html           | Interactive map visualizing scan results             |
| security_report.txt   | Summary report with vulnerability findings           |

---

## 📸 Sample Outputs

### 🌍 Interactive Security Map

![Demo pic](https://github.com/user-attachments/assets/7a47510b-b8e4-4ccc-848d-6d946f93d4f3)

---

### 📊 CSV Output Sample
```csv
ip,country,city,org,services,vulnerabilities
8.8.8.8,US,Mountain View,Google LLC,"DNS,HTTPS",0
1.1.1.1,AU,Sydney,Cloudflare Inc.,"DNS,HTTPS",0
```

---

# 🛡 IP SECURITY ASSESSMENT REPORT

---

*📅 Scan Date:* 2023-11-20 09:45:12  
*🌐 Total IPs Scanned:* 42  
*🚨 Vulnerable Hosts Found:* 3 (7.14%)

---

## ⚠ CRITICAL FINDINGS

- 203.0.113.45 - 2 vulnerabilities  
  • CVE-2023-1234  
  • CVE-2023-5678

- 198.51.100.22 - 1 vulnerability  
  • CVE-2023-9012

---

## 🛠 RECOMMENDATIONS

1. Patch vulnerable systems immediately  
2. Block suspicious IP: 203.0.113.45  
3. Review firewall rules for port 22 access  

---

## 📝 Notes & Limitations
---

### ✅ Permission Requirements

- Requires *admin/root* privileges for packet capture  
- Wireshark must be properly installed  
- tshark must be correctly configured in the system path  

---

### 📉 API Limitations

```python
# Free tier limits:
IPINFO_LIMIT = 50_000  # requests/month
SHODAN_LIMIT = 100     # scans/month
```

### Scanning Scope:
- only scans public ip addresses
- Vulnerability data depends on the Shodan's database
- Not all sevies may be identified

---

## License
[MIT LICENSE](https://github.com/Zareen1101/geolocator/edit/main/README.md)

---
