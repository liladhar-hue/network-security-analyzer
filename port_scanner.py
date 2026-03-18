import socket
import nmap
from datetime import datetime

# ─────────────────────────────────────────
# MAC Manufacturer Database
# ─────────────────────────────────────────
MAC_VENDORS = {
    "AC:22:0B": "Hikvision (IP Camera)",
    "00:40:8C": "Axis (IP Camera)",
    "00:50:56": "VMware (Virtual Machine)",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "00:1A:11": "Google (Chromecast/TV)",
    "F4:F5:D8": "Google (Chromecast/TV)",
    "00:17:88": "Philips Hue (IoT)",
    "00:11:32": "Synology (NAS)",
    "00:26:B9": "Dell",
    "3C:D9:2B": "Hewlett Packard (Printer)",
    "00:1B:A9": "Brother (Printer)",
    "00:0D:93": "Apple",
    "00:50:F2": "Microsoft",
}

# ─────────────────────────────────────────
# Port Database — what each port means
# ─────────────────────────────────────────
PORT_INFO = {
    21:   {"service": "FTP",         "risk": "HIGH",   "reason": "File transfer, often weak credentials"},
    22:   {"service": "SSH",         "risk": "MEDIUM", "reason": "Remote access, check for weak passwords"},
    23:   {"service": "Telnet",      "risk": "HIGH",   "reason": "Unencrypted remote access!"},
    25:   {"service": "SMTP",        "risk": "MEDIUM", "reason": "Mail server"},
    80:   {"service": "HTTP",        "risk": "MEDIUM", "reason": "Web interface, check for default login"},
    443:  {"service": "HTTPS",       "risk": "LOW",    "reason": "Secure web interface"},
    554:  {"service": "RTSP",        "risk": "HIGH",   "reason": "IP Camera stream!"},
    3306: {"service": "MySQL",       "risk": "HIGH",   "reason": "Database exposed!"},
    3389: {"service": "RDP",         "risk": "HIGH",   "reason": "Remote Desktop, brute force risk"},
    8000: {"service": "HTTP-ALT",    "risk": "MEDIUM", "reason": "Alternative web interface"},
    8080: {"service": "HTTP-Proxy",  "risk": "MEDIUM", "reason": "Web proxy or camera interface"},
    8554: {"service": "RTSP-ALT",    "risk": "HIGH",   "reason": "Alternative camera stream!"},
    9100: {"service": "RAW Print",   "risk": "HIGH",   "reason": "Printer directly exposed!"},
    1433: {"service": "MSSQL",       "risk": "HIGH",   "reason": "Database exposed!"},
    5900: {"service": "VNC",         "risk": "HIGH",   "reason": "Remote desktop, often no password!"},
}

# ─────────────────────────────────────────
# Weak Device Signatures
# ─────────────────────────────────────────
WEAK_DEVICE_SIGNATURES = {
    "IP Camera":  [554, 8554, 8080],
    "Printer":    [9100, 515, 631],
    "Router":     [23, 80, 443],
    "Database":   [3306, 1433],
    "Remote":     [3389, 5900],
    "IoT Device": [1883, 8883, 5683],
}


def get_manufacturer(mac):
    """Identify device manufacturer from MAC address"""
    if mac == "Unknown":
        return "Unknown Manufacturer"
    prefix = mac[:8].upper()
    return MAC_VENDORS.get(prefix, "Unknown Manufacturer")


def identify_device_type(open_ports):
    """Guess device type from open ports"""
    identified = []
    for device_type, signature_ports in WEAK_DEVICE_SIGNATURES.items():
        matches = [p for p in signature_ports if p in open_ports]
        if matches:
            identified.append(device_type)
    return identified if identified else ["General Device"]


def scan_ports(ip, ports=None):
    """Scan ports on a device using nmap"""
    nm = nmap.PortScanner()

    if ports is None:
        # Scan most common/important ports
        port_list = ",".join(str(p) for p in PORT_INFO.keys())
    else:
        port_list = ",".join(str(p) for p in ports)

    nm.scan(ip, arguments=f'-p {port_list} -T4')

    open_ports = []

    if ip in nm.all_hosts():
        for proto in nm[ip].all_protocols():
            for port in nm[ip][proto].keys():
                state = nm[ip][proto][port]['state']
                if state == 'open':
                    info = PORT_INFO.get(port, {
                        "service": nm[ip][proto][port].get('name', 'Unknown'),
                        "risk":    "LOW",
                        "reason":  "Unknown service"
                    })
                    open_ports.append({
                        "port":    port,
                        "service": info["service"],
                        "risk":    info["risk"],
                        "reason":  info["reason"]
                    })

    return open_ports


def analyze_device(device):
    """Full analysis of a single device"""
    ip  = device['ip']
    mac = device['mac']

    print(f"\n{'='*60}")
    print(f"  🔍 Analyzing: {ip}")
    print(f"{'='*60}")
    print(f"  MAC Address  : {mac}")

    # Manufacturer from MAC
    manufacturer = get_manufacturer(mac)
    print(f"  Manufacturer : {manufacturer}")

    # Scan ports
    print(f"  Scanning ports...")
    open_ports = scan_ports(ip)

    if not open_ports:
        print(f"  [-] No interesting ports found")
        return {
            "ip":           ip,
            "mac":          mac,
            "manufacturer": manufacturer,
            "device_type":  ["General Device"],
            "open_ports":   [],
            "risk_level":   "LOW"
        }

    # Identify device type
    port_numbers = [p['port'] for p in open_ports]
    device_types = identify_device_type(port_numbers)

    # Overall risk level
    risks = [p['risk'] for p in open_ports]
    if "HIGH" in risks:
        overall_risk = "🔴 HIGH"
    elif "MEDIUM" in risks:
        overall_risk = "🟡 MEDIUM"
    else:
        overall_risk = "🟢 LOW"

    # Display results
    print(f"  Device Type  : {', '.join(device_types)}")
    print(f"  Risk Level   : {overall_risk}")
    print(f"\n  Open Ports:")
    print(f"  {'Port':<8} {'Service':<15} {'Risk':<10} Reason")
    print(f"  {'-'*55}")

    for p in open_ports:
        print(f"  {p['port']:<8} {p['service']:<15} {p['risk']:<10} {p['reason']}")

    return {
        "ip":           ip,
        "mac":          mac,
        "manufacturer": manufacturer,
        "device_type":  device_types,
        "open_ports":   open_ports,
        "risk_level":   overall_risk
    }


def scan_all_devices(devices):
    """Scan all devices found in network"""
    print(f"\n[*] Starting Port Scan on {len(devices)} devices")
    print(f"[*] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    results = []
    for device in devices:
        result = analyze_device(device)
        results.append(result)

    # Summary
    print(f"\n{'='*60}")
    print(f"  📊 SCAN SUMMARY")
    print(f"{'='*60}")
    print(f"  {'IP':<18} {'Type':<20} {'Risk'}")
    print(f"  {'-'*55}")
    for r in results:
        print(f"  {r['ip']:<18} {r['device_type'][0]:<20} {r['risk_level']}")

    high_risk = [r for r in results if "HIGH" in r['risk_level']]
    if high_risk:
        print(f"\n  ⚠️  HIGH RISK DEVICES: {len(high_risk)}")
        for r in high_risk:
            print(f"     → {r['ip']} ({r['device_type'][0]})")

    return results
