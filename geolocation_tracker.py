import subprocess
import ipaddress
import os
import requests
import time
import pandas as pd
import folium
import webbrowser  # This was missing!
from collections import defaultdict

# Configuration
TSHARK_PATH = r"D:\Wireshark\tshark.exe"
PCAP_FILE = "network_capture.pcap"
INTERFACE = "Wi-Fi"
IPINFO_TOKEN = "d83dea9c5f2855"

def clean_ip(ip_str):
    """Sanitize and validate IP addresses"""
    if not ip_str:
        return None
    ip_str = ip_str.strip()
    try:
        return ip_str if not ipaddress.ip_address(ip_str).is_private else None
    except ValueError:
        return None

def capture_traffic():
    """Capture network traffic"""
    if os.path.exists(PCAP_FILE):
        os.remove(PCAP_FILE)
    
    print(f"📡 Capturing on {INTERFACE} (15 seconds)...")
    cmd = f'"{TSHARK_PATH}" -i {INTERFACE} -a duration:15 -w {PCAP_FILE}'
    proc = subprocess.Popen(cmd, shell=True)
    
    # Generate test traffic
    test_sites = ["https://google.com", "https://amazon.com", "https://github.com"]
    for url in test_sites:
        try: requests.get(url, timeout=2)
        except: pass
    
    time.sleep(2)
    proc.terminate()

def extract_ips():
    """Extract unique public IPs"""
    cmd = f'"{TSHARK_PATH}" -r {PCAP_FILE} -Y "ip" -T fields -e ip.src -e ip.dst'
    output = subprocess.check_output(cmd, shell=True).decode()
    
    ips = set()
    for line in output.split('\n'):
        if '\t' in line:
            src, dst = map(clean_ip, line.split('\t'))
            ips.update({ip for ip in (src, dst) if ip})
    
    return list(ips)

def geolocate_ips(ip_list):
    """Get geolocation data"""
    locations = []
    print("🌍 Geolocating IPs...")
    
    for ip in ip_list:
        try:
            url = f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}"
            response = requests.get(url).json()
            loc = response.get('loc', '').split(',')
            locations.append({
                'ip': ip,
                'city': response.get('city', 'Unknown'),
                'region': response.get('region', 'Unknown'),
                'country': response.get('country', 'XX'),
                'org': response.get('org', 'Unknown'),
                'lat': float(loc[0]) if loc and loc[0] else None,
                'lon': float(loc[1]) if len(loc)>1 and loc[1] else None
            })
        except Exception as e:
            print(f"⚠️ Error processing {ip}: {str(e)}")
    
    return pd.DataFrame(locations)

def create_map(geo_data):
    """Generate interactive map"""
    if geo_data.empty:
        print("❌ No valid locations to map")
        return
    
    valid_locs = geo_data.dropna(subset=['lat', 'lon'])
    if valid_locs.empty:
        print("❌ No coordinates available for mapping")
        return
    
    m = folium.Map(
        location=[valid_locs['lat'].mean(), valid_locs['lon'].mean()],
        zoom_start=2,
        tiles='CartoDB positron'
    )
    
    for _, row in valid_locs.iterrows():
        folium.Marker(
            [row['lat'], row['lon']],
            popup=f"<b>IP:</b> {row['ip']}<br><b>Org:</b> {row['org']}",
            icon=folium.Icon(color='blue')
        ).add_to(m)
    
    map_file = "ip_map.html"
    m.save(map_file)
    print(f"🗺️ Map saved to {map_file}")
    webbrowser.open(f'file://{os.path.abspath(map_file)}')

def generate_report(geo_data):
    """Create summary report with proper Unicode handling"""
    report = ["IP Geolocation Report", "="*40]
    
    if not geo_data.empty:
        report.extend([
            f"Total IPs: {len(geo_data)}",
            f"Countries: {', '.join(geo_data['country'].unique())}",
            "\nTop Organizations:",
            geo_data['org'].value_counts().head(5).to_string()
        ])
    
    with open("report.txt", "w", encoding='utf-8') as f:
        f.write("\n".join(report))
    print("Report saved to report.txt")


if __name__ == "__main__":
    capture_traffic()
    
    if os.path.exists(PCAP_FILE):
        ips = extract_ips()
        if ips:
            geo_data = geolocate_ips(ips)
            geo_data.to_csv("geolocations.csv", index=False)
            print("💾 Geolocation data saved to geolocations.csv")
            
            create_map(geo_data)
            generate_report(geo_data)
        else:
            print("❌ No public IPs found")
    else:
        print("❌ Capture failed")
        