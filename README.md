# IP Geolocation Tracker

A Python script that captures network traffic, extracts public IP addresses, and visualizes their geographic locations on an interactive map.

## Features

- 📡 Captures live network traffic using Wireshark's `tshark` utility
- 🌍 Geolocates public IP addresses using the ipinfo.io API
- 🗺 Generates interactive Folium maps showing IP locations
- 📊 Creates summary reports with IP details and organization information
- 💾 Saves geolocation data to CSV for further analysis

## Requirements

- Python 3.6+
- Wireshark (with `tshark` in system PATH)
- Required Python packages:
  - ipaddress
  - requests
  - pandas
  - folium

## Installation

1. Install Wireshark from [https://www.wireshark.org/](https://www.wireshark.org/)
2. Clone this repository:
   bash
   git clone https://github.com/yourusername/ip-geolocation-tracker.git
   cd ip-geolocation-tracker
   
3. Install Python dependencies:
   bash
   pip install requests pandas folium
   

## Configuration

1. Edit the script to set your Wireshark `tshark` path:
   python
   TSHARK_PATH = r"D:\Wireshark\tshark.exe"  # Update this path
   

2. Get a free API token from [ipinfo.io](https://ipinfo.io/) and update:
   python
   IPINFO_TOKEN = "your_token_here"
   

3. Set your network interface name (optional):
   python
   INTERFACE = "Wi-Fi"  # Change to your interface (Ethernet, eth0, etc.)
   

## Usage

Run the script:
bash
python ip_geolocator.py


The script will:
1. Capture network traffic for 15 seconds
2. Extract public IP addresses
3. Geolocate each IP address
4. Generate:
   - `geolocations.csv` with all IP details
   - `ip_map.html` interactive map
   - `report.txt` summary report

## Output Samples

### Interactive Map
![Demo pic](https://github.com/user-attachments/assets/56e30d77-c46e-4c0c-9808-7eb9cb85cd7c)

### CSV File
csv
ip,city,region,country,org,lat,lon
8.8.8.8,Mountain View,California,US,Google LLC,37.4056,-122.0775


### Report

IP Geolocation Report
========================================
Total IPs: 15
Countries: US, DE, FR, JP

Top Organizations:
Google LLC         3
Amazon.com, Inc.   2
Microsoft Corp.    2


## Limitations

- Requires admin privileges for packet capture
- Free ipinfo.io accounts have 50,000 monthly requests limit
- Only captures public IP addresses (filters out private IPs)

## License

[MIT License](https://github.com/Zareen1101/geolocator/blob/main/LICENSE)

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you'd like to change.
