from network_monitoring import get_active_interface
from device_scanner import scan_network, display_devices
from port_scanner import scan_all_devices
from vulnerability import check_all_devices

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

    # Step 4 - Vulnerability detection
    vuln_results = check_all_devices(scan_results)
