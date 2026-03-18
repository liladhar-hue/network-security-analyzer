import scapy.all as scapy
import nmap
import socket

def scan_with_arp(ip_range):
    """Fast scan - works on simple networks like home WiFi"""
    print("[*] Trying ARP scan...")
    
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, unanswered = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)

    devices = []

    for sent, received in answered:
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except:
            hostname = "Unknown"

        devices.append({
            "ip":       received.psrc,
            "mac":      received.hwsrc,
            "hostname": hostname,
            "method":   "ARP"
        })

    return devices


def scan_with_nmap(ip_range):
    """Deeper scan - works on complex networks like hotspot/college WiFi"""
    print("[*] Trying Nmap scan...")

    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-sn')

    devices = []

    for host in nm.all_hosts():
        try:
            hostname = socket.gethostbyaddr(host)[0]
        except:
            hostname = "Unknown"

        mac = "Unknown"
        if 'mac' in nm[host]['addresses']:
            mac = nm[host]['addresses']['mac']

        devices.append({
            "ip":       host,
            "mac":      mac,
            "hostname": hostname,
            "method":   "Nmap"
        })

    return devices


def scan_network(ip_range):
    print(f"\n[*] Scanning network: {ip_range}")
    print("[*] Please wait...\n")

    # First try ARP (fast)
    devices = scan_with_arp(ip_range)

    if devices:
        print("[+] ARP scan successful!")
        return devices
    
    # ARP failed → fallback to Nmap
    print("[-] ARP scan found nothing, switching to Nmap...\n")
    devices = scan_with_nmap(ip_range)

    return devices


def display_devices(devices):
    if not devices:
        print("[-] No devices found on the network")
        return

    print(f"\n{'No.':<5} {'IP Address':<18} {'MAC Address':<22} {'Hostname':<25} {'Method'}")
    print("-" * 80)

    for i, device in enumerate(devices, 1):
        print(f"{i:<5} {device['ip']:<18} {device['mac']:<22} {device['hostname']:<25} {device['method']}")

    print("-" * 80)
    print(f"[+] Total devices found: {len(devices)}")

