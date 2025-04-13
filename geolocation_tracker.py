import subprocess
import ipaddress
import os
import requests
import time
import pandas as pd
import folium
import webbrowser
from collections import defaultdict

# Configuration
TSHARK_PATH = r"D:\Wireshark\tshark.exe"
PCAP_FILE = "network_capture.pcap"
INTERFACE = "Wi-Fi"
IPINFO_TOKEN = "###############"
SHODAN_API_KEY = "#########################" 

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

def scan_vulnerabilities(ip):
    """Check for known vulnerabilities using Shodan"""
    try:
        if not SHODAN_API_KEY:
            return {"error": "Shodan API key not configured"}
            
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        response = requests.get(url, timeout=10)
        data = response.json()
        
        vulns = []
        if 'vulns' in data:
            for cve, info in data['vulns'].items():
                vulns.append({
                    'cve': cve,
                    'summary': info.get('summary', 'No description available'),
                    'verified': info.get('verified', False)
                })
        
        return {
            'ports': data.get('ports', []),
            'vulnerabilities': vulns,
            'services': [service.get('product', 'Unknown') for service in data.get('data', [])]
        }
    except Exception as e:
        return {"error": str(e)}

def geolocate_ips(ip_list):
    """Get geolocation and vulnerability data"""
    locations = []
    print("🌍 Geolocating IPs and scanning for vulnerabilities...")
    
    for ip in ip_list:
        try:
            # Get geolocation data
            geo_url = f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}"
            geo_response = requests.get(geo_url).json()
            loc = geo_response.get('loc', '').split(',')
            
            # Get vulnerability data
            vuln_data = scan_vulnerabilities(ip)
            
            locations.append({
                'ip': ip,
                'city': geo_response.get('city', 'Unknown'),
                'region': geo_response.get('region', 'Unknown'),
                'country': geo_response.get('country', 'XX'),
                'org': geo_response.get('org', 'Unknown'),
                'lat': float(loc[0]) if loc and loc[0] else None,
                'lon': float(loc[1]) if len(loc)>1 and loc[1] else None,
                'open_ports': vuln_data.get('ports', []),
                'services': ', '.join(vuln_data.get('services', [])),
                'vulnerabilities': len(vuln_data.get('vulnerabilities', [])),
                'vulnerability_details': vuln_data.get('vulnerabilities', [])
            })
        except Exception as e:
            print(f"⚠ Error processing {ip}: {str(e)}")
    
    return pd.DataFrame(locations)

def create_map(geo_data):
    """Generate interactive map with vulnerability info"""
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
        vuln_text = "No vulnerabilities found"
        if row['vulnerabilities'] > 0:
            vuln_text = f"<b>{row['vulnerabilities']} vulnerabilities found</b><br>"
            for vuln in row['vulnerability_details'][:3]:  # Show first 3
                vuln_text += f"• {vuln['cve']}: {vuln['summary'][:100]}...<br>"
            if row['vulnerabilities'] > 3:
                vuln_text += f"...and {row['vulnerabilities']-3} more"
        
        folium.Marker(
            [row['lat'], row['lon']],
            popup=f"""
            <b>IP:</b> {row['ip']}<br>
            <b>Org:</b> {row['org']}<br>
            <b>Services:</b> {row['services']}<br>
            {vuln_text}
            """,
            icon=folium.Icon(
                color='red' if row['vulnerabilities'] > 0 else 'green',
                icon='shield' if row['vulnerabilities'] > 0 else 'ok-sign'
            )
        ).add_to(m)
    
    map_file = "ip_map.html"
    m.save(map_file)
    print(f"🗺 Map saved to {map_file}")
    webbrowser.open(f'file://{os.path.abspath(map_file)}')

def generate_report(geo_data):
    """Create enhanced security report"""
    report = [
        "IP SECURITY ASSESSMENT REPORT",
        "="*40,
        f"Generated: {pd.Timestamp.now()}",
        f"Total IPs analyzed: {len(geo_data)}",
        f"IPs with vulnerabilities: {len(geo_data[geo_data['vulnerabilities'] > 0])}"
    ]
    
    if not geo_data.empty:
        # Top vulnerable IPs
        vuln_ips = geo_data[geo_data['vulnerabilities'] > 0].sort_values(
            'vulnerabilities', ascending=False)
        
        if not vuln_ips.empty:
            report.extend([
                "\nTOP VULNERABLE HOSTS:",
                vuln_ips[['ip', 'org', 'vulnerabilities']].to_string(index=False)
            ])
            
            # List unique CVEs found
            all_vulns = []
            for _, row in vuln_ips.iterrows():
                all_vulns.extend(row['vulnerability_details'])
            
            if all_vulns:
                report.append("\nUNIQUE VULNERABILITIES FOUND:")
                for vuln in all_vulns[:10]:  # Limit to top 10
                    report.append(
                        f"{vuln['cve']}: {vuln['summary'][:150]}..."
                    )
        
        # Network summary
        report.extend([
            "\nNETWORK SUMMARY:",
            f"Countries: {', '.join(geo_data['country'].unique())}",
            "\nTop Organizations:",
            geo_data['org'].value_counts().head(5).to_string()
        ])
    
    with open("security_report.txt", "w", encoding='utf-8') as f:
        f.write("\n".join(report))
    print("📝 Security report saved to security_report.txt")

if _name_ == "_main_":
    capture_traffic()
    
    if os.path.exists(PCAP_FILE):
        ips = extract_ips()
        if ips:
            geo_data = geolocate_ips(ips)
            geo_data.to_csv("security_scan_results.csv", index=False)
            print("💾 Security scan data saved to security_scan_results.csv")
            
            create_map(geo_data)
            generate_report(geo_data)
        else:
            print("❌ No public IPs found")
    else:
        print("❌ Capture failed")
