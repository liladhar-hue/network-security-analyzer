from network_monitoring import get_active_interface
from device_scanner import scan_network, display_devices
from port_scanner import scan_all_devices
from vulnerability import check_all_devices
from cve_lookup import lookup_cves_for_services, print_cve_report


if __name__ == "__main__":
    # Step 1 - Get your IP
    interface, ip = get_active_interface()

    if not interface:
        print("[-] No active interface found")
        exit()

    print(f"[+] Active Interface : {interface}")
    print(f"[+] Your IP Address  : {ip}")

    # Build IP range
    ip_range = ".".join(ip.split(".")[:3]) + ".0/24"

    # Step 2 - Scan network
    devices = scan_network(ip_range)
    display_devices(devices)

    if not devices:
        print("[-] No devices found. Exiting.")
        exit()

    # Step 3 - Port scan
    scan_results = scan_all_devices(devices)

    if not scan_results:
        print("[-] No open ports found.")
        exit()

    # Step 4 - Vulnerability detection
    vuln_results = check_all_devices(scan_results)

    # Step 5 - CVE Lookup
    print("\n" + "="*60)
    print("  STARTING CVE LOOKUP")
    print("="*60)

    cve_results = {}

    for device_ip, ports in scan_results.items():
        print(f"\n[+] Processing {device_ip}...")

        # Optional: clean service names (better CVE search)
        cleaned_ports = {}
        for port, service in ports.items():
            cleaned_service = service.split()[0]  # e.g. "OpenSSH 8.2" → "OpenSSH"
            cleaned_ports[port] = cleaned_service

        cve_results[device_ip] = lookup_cves_for_services(cleaned_ports)

    # Step 6 - Print CVE Reports
    for device_ip, results in cve_results.items():
        print(f"\n{'='*60}")
        print(f"  CVE REPORT FOR {device_ip}")
        print(f"{'='*60}")
        print_cve_report(results)
