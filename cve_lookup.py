import requests
import time

NVD_API_KEY = "d7e80c2a-6b17-450f-b3d8-3bc136800594"  
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def search_cves(keyword: str, max_results: int = 5) -> list:
    headers = {"apiKey": NVD_API_KEY}
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results
    }

    try:
        response = requests.get(NVD_BASE_URL, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")
            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description available"
            )
            metrics = cve.get("metrics", {})
            cvss_score = "N/A"
            severity = "N/A"

            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_score = cvss.get("baseScore", "N/A")
                severity = cvss.get("baseSeverity", "N/A")
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_score = cvss.get("baseScore", "N/A")
                severity = metrics["cvssMetricV2"][0].get("baseSeverity", "N/A")

            cves.append({
                "id": cve_id,
                "description": description[:200],
                "score": cvss_score,
                "severity": severity
            })

        return cves

    except requests.exceptions.Timeout:
        print(f"  [!] Timeout fetching CVEs for '{keyword}'")
        return []
    except requests.exceptions.RequestException as e:
        print(f"  [!] Error fetching CVEs: {e}")
        return []

def lookup_cves_for_services(open_ports: dict) -> dict:
    """
    open_ports format:
    { 22: 'OpenSSH 8.2', 80: 'Apache httpd 2.4.41', 443: 'nginx 1.18' }
    """
    results = {}

    for port, service in open_ports.items():
        print(f"  [*] Looking up CVEs for port {port} ({service})...")
        cves = search_cves(service)
        results[port] = {
            "service": service,
            "cves": cves
        }
        time.sleep(1)  # respect rate limits

    return results

def print_cve_report(cve_results: dict):
    print("\n" + "="*60)
    print("  CVE VULNERABILITY REPORT")
    print("="*60)

    for port, data in cve_results.items():
        print(f"\n  Port {port} — {data['service']}")
        print(f"  {'-'*40}")

        if not data["cves"]:
            print("  No CVEs found.")
            continue

        for cve in data["cves"]:
            severity_color = {
                "CRITICAL": "[CRITICAL]",
                "HIGH":     "[HIGH]    ",
                "MEDIUM":   "[MEDIUM]  ",
                "LOW":      "[LOW]     ",
            }.get(cve["severity"], "[UNKNOWN] ")

            print(f"  {severity_color} {cve['id']} (Score: {cve['score']})")
            print(f"  {cve['description'][:120]}...")
            print()
