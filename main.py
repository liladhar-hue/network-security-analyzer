from network_monitoring import get_active_interface
from device_scanner import scan_network, display_devices
from port_scanner import scan_all_devices
from vulnerability import check_all_devices
from cve_lookup import lookup_cves_for_services, print_cve_report


def iter_devices(scan_results):
    """
    Supports:
    1) list of dicts:
       [{"ip": "...", "ports": {...}}]

    2) dict:
       {"ip": {...}}
    """
    if isinstance(scan_results, dict):
        for ip, info in scan_results.items():
            if isinstance(info, dict) and "ports" in info:
                yield ip, info.get("ports", {})
            elif isinstance(info, dict):
                yield ip, info
            else:
                yield ip, {}

    elif isinstance(scan_results, list):
        for device in scan_results:
            if not isinstance(device, dict):
                continue

            ip = (
                device.get("ip")
                or device.get("ip_address")
                or device.get("IP")
                or "Unknown"
            )
            ports = device.get("ports", {})
            yield ip, ports


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
        print("\n[✓] Scan completed")
        print("[ℹ] No devices found on the network")
        exit()

    # Step 3 - Port scan
    scan_results = scan_all_devices(devices)

    if not scan_results:
        print("\n[✓] Scan completed")
        print("[ℹ] No open ports detected on any device")
        exit()

    # Step 4 - Vulnerability detection
    vuln_results = check_all_devices(scan_results)

    # Step 5 - CVE Lookup
    print("\n" + "=" * 60)
    print("  STARTING CVE LOOKUP")
    print("=" * 60)

    cve_results = {}
    any_ports_found = False

    for device_ip, ports in iter_devices(scan_results):
        if not ports:
            print(f"\n[!] {device_ip}: No open ports found — skipping CVE lookup")
            continue

        any_ports_found = True
        print(f"\n[+] Processing {device_ip}...")

        cleaned_ports = {}
        for port, service in ports.items():
            cleaned_ports[int(port)] = str(service).strip()

        cve_results[device_ip] = lookup_cves_for_services(cleaned_ports)

    # Final Output Handling
    if not any_ports_found:
        print("\n[✓] Scan completed successfully")
        print("[ℹ] No services detected on any device")
        print("[ℹ] CVE lookup skipped due to lack of input data")

    elif not cve_results:
        print("\n[!] CVE lookup completed but no results found")

    else:
        for device_ip, results in cve_results.items():
            print(f"\n{'=' * 60}")
            print(f"  CVE REPORT FOR {device_ip}")
            print(f"{'=' * 60}")
            print_cve_report(results)
