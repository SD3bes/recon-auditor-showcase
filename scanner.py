#!/usr/bin/env python3
"""
Enterprise Network Recon, OSINT, Geolocation & Vulnerability Auditor (v5.5)
Author: Ziad A. (Cybersecurity Engineering Portfolio)
"""

import socket
import ssl
import sys
import time
import subprocess
import re
import os
import json
import urllib.request
import urllib.error
import concurrent.futures
from datetime import datetime

# Enable ANSI colors for Windows terminals
if sys.platform == "win32":
    os.system("color")

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

BANNER_ART = f"""{CYAN}{BOLD}
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ███████╗██║     ███████║██╔██╗ ██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚██╗██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{RESET}{DIM}  [ Reconnaissance | Geolocation & ASN | OS Fingerprint | Risk Auditor v5.5 ]{RESET}
"""

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]

IIS_OS_MAP = {
    "10.0": "Windows Server 2016 / 2019 / 2022 / Windows 10/11",
    "8.5":  "Windows Server 2012 R2 / Windows 8.1",
    "8.0":  "Windows Server 2012 / Windows 8",
    "7.5":  "Windows Server 2008 R2 / Windows 7",
    "7.0":  "Windows Server 2008 / Windows Vista",
    "6.0":  "Windows Server 2003 (Legacy EOL)",
    "5.0":  "Windows 2000 Server (Legacy EOL)"
}

CVE_KNOWLEDGE_BASE = [
    (r"Apache/2\.4\.(49|50)", "CVE-2021-41773", 9.8, "Apache HTTP Server Path Traversal & RCE"),
    (r"OpenSSH_7\.[0-4]", "CVE-2016-0777", 7.5, "OpenSSH Roaming Client Information Disclosure"),
    (r"OpenSSH_8\.[0-4]", "CVE-2020-14145", 5.9, "OpenSSH Observable Discrepancy Information Leak"),
    (r"Microsoft-IIS/6\.0", "CVE-2017-7269", 9.8, "Windows Server 2003 WebDAV Buffer Overflow"),
    (r"nginx/1\.14\.", "CVE-2018-16843", 7.5, "NGINX HTTP/2 Excessive Memory Consumption DoS"),
    (r"ProFTPD 1\.3\.5", "CVE-2015-3306", 9.8, "ProFTPD mod_copy Arbitrary File Copy Vulnerability"),
    (r"vsftpd 2\.3\.4", "CVE-2011-2523", 9.8, "vsftpd Smile Backdoor Incident Signature")
]

SENSITIVE_PATHS = [
    ("/.env", "Environment Secrets Configuration File", "CRITICAL", 9.5),
    ("/.git/HEAD", "Exposed Git Source Code Repository", "HIGH", 8.5),
    ("/server-status", "Apache Server Status Metrics Interface", "MEDIUM", 5.0),
    ("/robots.txt", "Robots Crawl Exclusion Map", "INFO", 0.0),
    ("/.well-known/security.txt", "Security Disclosure Contact Policy", "INFO", 0.0)
]

# --- Module 1: Geolocation, ASN & Company Origin ---

def lookup_geolocation_and_company(ip: str):
    """
    Queries public IP geolocation endpoint to extract geographic coordinates,
    origin country, ISP, and host enterprise organization.
    """
    # Exclude private IP ranges from external API lookup
    if ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3", "127.")):
        return {
            "country": "Local Private Subnet",
            "country_code": "LAN",
            "city": "Internal Intranet",
            "region": "Private Network",
            "isp": "RFC1918 Private Addressing",
            "org": "Internal Enterprise Host",
            "as": "Private Autonomous System"
        }

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as"
        req = urllib.request.Request(url, headers={"User-Agent": "ReconAuditor/5.5"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown Country"),
                    "country_code": data.get("countryCode", "??"),
                    "city": data.get("city", "Unknown City"),
                    "region": data.get("regionName", ""),
                    "isp": data.get("isp", "Unknown ISP"),
                    "org": data.get("org", data.get("isp", "Unknown Org")),
                    "as": data.get("as", "Unknown ASN")
                }
    except Exception:
        pass

    return {
        "country": "Lookup Timed Out",
        "country_code": "N/A",
        "city": "Unknown",
        "region": "N/A",
        "isp": "Unknown Provider",
        "org": "Undetermined Entity",
        "as": "N/A"
    }

def estimate_os_via_ttl(target_ip: str) -> str:
    try:
        cmd = ["ping", "-n", "1", target_ip] if sys.platform == "win32" else ["ping", "-c", "1", target_ip]
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True, timeout=2.5)
        match = re.search(r"TTL=(\d+)", output, re.IGNORECASE)
        if match:
            ttl = int(match.group(1))
            if ttl <= 64:
                return f"Linux / Unix / macOS (TTL: {ttl})"
            elif ttl <= 128:
                return f"Microsoft Windows (TTL: {ttl})"
            elif ttl <= 255:
                return f"Cisco IOS / Network Appliance (TTL: {ttl})"
            return f"Custom Stack (TTL: {ttl})"
    except Exception:
        pass
    return "Undetermined (ICMP Filtered)"

# --- Module 2: Target Intelligence & Geolocation ---

def resolve_and_geolocate_target(target: str):
    print(f"\n{BOLD}{MAGENTA}[*] STAGE 1: Target Resolution, Origin Country & Geolocation{RESET}")
    print(f"{DIM}─" * 70 + f"{RESET}")
    try:
        ip = socket.gethostbyname(target)
        print(f"  {CYAN}▸ Target Host       :{RESET} {target}")
        print(f"  {CYAN}▸ Target IPv4       :{RESET} {ip}")
    except socket.gaierror:
        print(f"  {RED}[!] Unable to resolve hostname: {target}{RESET}")
        return None, None

    try:
        ptr = socket.gethostbyaddr(ip)[0]
        print(f"  {CYAN}▸ Reverse DNS (PTR) :{RESET} {ptr}")
    except socket.herror:
        print(f"  {CYAN}▸ Reverse DNS (PTR) :{RESET} {DIM}None configured{RESET}")

    # Country & Organization Lookup
    geo = lookup_geolocation_and_company(ip)
    print(f"  {CYAN}▸ Host Country      :{RESET} {BOLD}{GREEN}{geo['country']} [{geo['country_code']}]{RESET}")
    print(f"  {CYAN}▸ Geographic City   :{RESET} {geo['city']}, {geo['region']}")
    print(f"  {CYAN}▸ Operating Entity  :{RESET} {BOLD}{YELLOW}{geo['org']}{RESET}")
    print(f"  {CYAN}▸ Network ASN & ISP :{RESET} {geo['as']} ({geo['isp']})")

    os_family = estimate_os_via_ttl(ip)
    print(f"  {CYAN}▸ ICMP OS Estimate  :{RESET} {YELLOW}{os_family}{RESET}")
    return ip, geo

# --- Module 3: Web Security, OSINT & Cryptography ---

def audit_tls_cryptography(target: str, findings: list):
    print(f"\n{BOLD}{MAGENTA}[*] STAGE 2: Cryptographic & Transport Security Inspection{RESET}")
    print(f"{DIM}─" * 70 + f"{RESET}")
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((target, 443), timeout=3.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                ver = ssock.version()
                cipher = ssock.cipher()
                print(f"  {GREEN}[+] TLS Handshake    :{RESET} {ver}")
                print(f"  {GREEN}[+] Active Cipher    :{RESET} {cipher[0]} ({cipher[2]} bits)")
                
                if ver in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                    findings.append({
                        "category": "Cryptography",
                        "severity": "HIGH",
                        "score": 7.5,
                        "title": f"Deprecated Protocol Active: {ver}",
                        "detail": "Obsolescent TLS versions violate PCI-DSS compliance and risk traffic interception."
                    })
    except Exception as e:
        print(f"  {DIM}[-] TLS probe skipped or port 443 unresponsive: {e}{RESET}")

def extract_web_and_osint(target: str, findings: list):
    print(f"\n{BOLD}{MAGENTA}[*] STAGE 3: Web Technology, OSINT & Exposure Inspection{RESET}")
    print(f"{DIM}─" * 70 + f"{RESET}")

    url = f"http://{target}"
    html_content = ""
    headers = {}

    try:
        req = urllib.request.Request(
            url, 
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) EnterpriseAuditor/5.5"}
        )
        with urllib.request.urlopen(req, timeout=3.5) as resp:
            headers = dict(resp.headers)
            html_content = resp.read(131072).decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"  {YELLOW}[-] HTTP probe on {url}: {e}{RESET}")

    server_header = headers.get("Server", "Not disclosed")
    print(f"  {CYAN}▸ Web Server Header :{RESET} {YELLOW}{server_header}{RESET}")

    iis_match = re.search(r"Microsoft-IIS/([\d\.]+)", server_header, re.IGNORECASE)
    if iis_match:
        ver = iis_match.group(1)
        mapped_os = IIS_OS_MAP.get(ver, "Windows Server (Unknown Version)")
        print(f"  {GREEN}[+] Windows Server  :{RESET} {BOLD}{mapped_os}{RESET} (via IIS/{ver})")
        if "Legacy EOL" in mapped_os:
            findings.append({
                "category": "Operating System",
                "severity": "CRITICAL",
                "score": 9.5,
                "title": "Legacy Windows Server (End-of-Life)",
                "detail": f"Host runs {mapped_os}, which no longer receives critical security updates."
            })

    # Sensitive path tests
    for path, label, sev, score in SENSITIVE_PATHS:
        test_url = f"http://{target}{path}"
        try:
            p_req = urllib.request.Request(test_url, headers={"User-Agent": "EnterpriseAuditor/5.5"}, method="HEAD")
            with urllib.request.urlopen(p_req, timeout=2.0) as p_resp:
                if p_resp.status == 200:
                    if sev == "INFO":
                        print(f"    {GREEN}[FOUND]{RESET} {path:<25} ({label})")
                    else:
                        print(f"    {RED}[EXPOSED]{RESET} {path:<25} ({label})")
                        findings.append({
                            "category": "Information Disclosure",
                            "severity": sev,
                            "score": score,
                            "title": f"Publicly Accessible Path: {path}",
                            "detail": f"{label} is publicly reachable without authentication."
                        })
        except Exception:
            pass

    # Contact OSINT
    if html_content:
        email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
        emails = {e.lower() for e in re.findall(email_pattern, html_content) if not e.endswith(('.png', '.jpg'))}
        
        tel_links = re.findall(r'href=["\']tel:([^"\']+)["\']', html_content, re.IGNORECASE)
        carrier_pattern = r'(?:(?:\+|00)\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)\d{3,4}[\s.-]?\d{3,4}'
        phones = set(tel_links) | {m.group(0).strip() for m in re.finditer(carrier_pattern, html_content) if 8 <= len(re.sub(r'\D', '', m.group(0))) <= 15}

        print(f"\n  {BOLD}{CYAN}OSINT Contact Data:{RESET}")
        print(f"    Emails Detected  : {CYAN}{', '.join(list(emails)[:3]) or 'None'}{RESET}")
        print(f"    Carrier / Phones : {CYAN}{', '.join(list(phones)[:3]) or 'None'}{RESET}")

# --- Module 4: Concurrent Port Scan & CVE Correlation ---

def grab_banner(target_ip: str, port: int, timeout: float = 0.8) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target_ip, port))
            if port in [80, 8080]:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            else:
                s.sendall(b"\r\n")
            raw = s.recv(1024).decode("utf-8", errors="ignore").strip()
            return raw.split("\n")[0][:50] if raw else "Open (No Banner)"
    except Exception:
        return "Open"

def scan_single_port(target_ip: str, port: int, timeout: float = 0.6):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((target_ip, port)) == 0:
                banner = grab_banner(target_ip, port)
                return port, True, banner
    except Exception:
        pass
    return port, False, None

def audit_ports_and_cves(target_ip: str, port_list: list, findings: list, max_workers: int = 150):
    print(f"\n{BOLD}{MAGENTA}[*] STAGE 4: Multi-Threaded Port Scan & CVE Correlation{RESET}")
    print(f"{DIM}─" * 70 + f"{RESET}")
    start = time.time()
    open_ports = []

    port_risks = {
        21:   ("MEDIUM", 5.5, "Unencrypted FTP Service", "Credentials transmitted in cleartext; enforce FTPS/SFTP."),
        23:   ("HIGH", 7.8, "Cleartext Telnet Service", "Insecure remote terminal; replace with SSH."),
        135:  ("HIGH", 7.5, "Exposed MS-RPC Endpoint", "Isolate RPC endpoints behind network firewalls."),
        139:  ("HIGH", 7.2, "Exposed NetBIOS Service", "Legacy NetBIOS session exposed; disable broadcast resolution."),
        445:  ("CRITICAL", 9.8, "Direct SMB Exposure", "Wormable exploit vector; block TCP 445 at edge boundaries."),
        3389: ("HIGH", 7.0, "Exposed RDP Port", "Remote desktop exposed; require MFA or restrict via VPN.")
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_single_port, target_ip, p): p for p in port_list}
        for f in concurrent.futures.as_completed(futures):
            port, is_open, banner = f.result()
            if is_open:
                open_ports.append((port, banner))
                print(f"  {GREEN}[+] PORT {port:<5} OPEN{RESET} │ {YELLOW}{banner}{RESET}")

                if port in port_risks:
                    sev, score, title, remedy = port_risks[port]
                    findings.append({
                        "category": "Perimeter Exposure",
                        "severity": sev,
                        "score": score,
                        "title": f"{title} (Port {port})",
                        "detail": remedy
                    })

                for pattern, cve_id, cvss, cve_desc in CVE_KNOWLEDGE_BASE:
                    if re.search(pattern, banner, re.IGNORECASE):
                        print(f"      {RED}↳ [CVE MATCH] {cve_id} (CVSS {cvss}): {cve_desc}{RESET}")
                        findings.append({
                            "category": "Known Vulnerability",
                            "severity": "CRITICAL" if cvss >= 9.0 else "HIGH",
                            "score": cvss,
                            "title": f"{cve_id} ({cve_desc})",
                            "detail": f"Captured banner '{banner}' matches vulnerable software version."
                        })

    duration = time.time() - start
    print(f"{DIM}─" * 70 + f"{RESET}")
    print(f"  {CYAN}Port scan finished in {duration:.2f}s. Discovered {len(open_ports)} listening ports.{RESET}")
    return open_ports

# --- Module 5: Executive Report Generator ---

def generate_html_report(target: str, ip: str, geo: dict, open_ports: list, findings: list, risk_index: float, grade: str):
    rows = ""
    for f in findings:
        badge_color = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#3b82f6"}.get(f["severity"], "#64748b")
        rows += f"""
        <tr>
            <td><span style="background:{badge_color}; color:#fff; padding:3px 8px; border-radius:4px; font-weight:bold; font-size:11px;">{f['severity']}</span></td>
            <td><strong>{f['title']}</strong></td>
            <td>{f['category']}</td>
            <td><code>{f['score']}</code></td>
            <td>{f['detail']}</td>
        </tr>
        """

    ports_rows = "".join([f"<tr><td><code>TCP {p[0]}</code></td><td>Open</td><td><code>{p[1]}</code></td></tr>" for p in open_ports])

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Audit Assessment - {target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #030611; color: #f8fafc; margin: 0; padding: 30px; }}
        .container {{ max-width: 950px; margin: 0 auto; background: #0a101f; padding: 30px; border-radius: 12px; border: 1px solid #1e293b; }}
        .header {{ border-bottom: 2px solid #1e293b; padding-bottom: 20px; margin-bottom: 25px; }}
        .geo-box {{ background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 15px; margin-bottom: 25px; font-size: 13px; display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
        .score-box {{ display: flex; gap: 15px; margin-bottom: 30px; }}
        .card {{ background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 15px; flex: 1; text-align: center; }}
        .card h3 {{ margin: 0; font-size: 12px; color: #94a3b8; text-transform: uppercase; }}
        .card .val {{ font-size: 26px; font-weight: bold; margin-top: 8px; color: #38bdf8; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }}
        th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #1e293b; }}
        th {{ background: #020617; color: #94a3b8; }}
        code {{ background: #1e293b; padding: 2px 6px; border-radius: 4px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 style="color:#00f2fe; margin:0 0 10px 0;">Perimeter Reconnaissance & Security Audit</h1>
            <p style="color:#94a3b8; margin:0;">Target: <strong>{target}</strong> ({ip}) | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="geo-box">
            <div><strong>Host Country:</strong> {geo.get('country', 'N/A')} [{geo.get('country_code', '??')}]</div>
            <div><strong>Geographic City:</strong> {geo.get('city', 'N/A')}, {geo.get('region', '')}</div>
            <div><strong>Operating Enterprise:</strong> {geo.get('org', 'N/A')}</div>
            <div><strong>Autonomous System (ASN):</strong> {geo.get('as', 'N/A')}</div>
        </div>

        <div class="score-box">
            <div class="card"><h3>Threat Exposure Index</h3><div class="val">{risk_index:.1f} / 100</div></div>
            <div class="card"><h3>Defensive Grade</h3><div class="val">{grade}</div></div>
            <div class="card"><h3>Flagged Risk Vectors</h3><div class="val">{len(findings)}</div></div>
        </div>

        <h2 style="color:#e2e8f0;">Identified Risks & Remediation Plan</h2>
        <table>
            <thead><tr><th>Severity</th><th>Vulnerability / Finding</th><th>Category</th><th>CVSS</th><th>Remediation Guidance</th></tr></thead>
            <tbody>{rows or "<tr><td colspan='5'>No critical security vectors flagged.</td></tr>"}</tbody>
        </table>

        <h2 style="color:#e2e8f0; margin-top:30px;">Discovered Services ({len(open_ports)})</h2>
        <table>
            <thead><tr><th>Port</th><th>Status</th><th>Banner Information</th></tr></thead>
            <tbody>{ports_rows or "<tr><td colspan='3'>No open listening ports detected.</td></tr>"}</tbody>
        </table>
    </div>
</body>
</html>"""

    report_path = "audit_report.html"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"\n  {GREEN}[✓] Standalone executive report exported to:{RESET} {BOLD}{os.path.abspath(report_path)}{RESET}")

# --- Main CLI Flow ---

def main():
    print(BANNER_ART)
    findings = []
    try:
        raw_target = input(f"{BOLD}Enter Target Host or IP (e.g. scanme.nmap.org): {RESET}").strip()
        if not raw_target:
            raw_target = "scanme.nmap.org"
            print(f"{DIM}Defaulting to demo host: {raw_target}{RESET}")

        ip, geo = resolve_and_geolocate_target(raw_target)
        if not ip:
            return

        audit_tls_cryptography(raw_target, findings)
        extract_web_and_osint(raw_target, findings)

        # Port Range Selection
        print(f"\n{BOLD}Select Port Scan Scope:{RESET}")
        print("  1. Fast Scan (Common administrative & web services - 18 ports)")
        print("  2. Standard Privileged Ports (1–1024)")
        print("  3. Custom Scope (e.g., 1–5000)")
        choice = input(f"{CYAN}Select option [1-3, default 1]: {RESET}").strip()

        if choice == "2":
            port_range = list(range(1, 1025))
            workers = 150
        elif choice == "3":
            start_p = int(input("Start port (e.g. 1): ").strip() or "1")
            end_p = int(input("End port (e.g. 5000): ").strip() or "1024")
            port_range = list(range(max(1, start_p), min(65536, end_p + 1)))
            workers = 200
        else:
            port_range = COMMON_PORTS
            workers = 50

        open_ports = audit_ports_and_cves(ip, port_range, findings, max_workers=workers)

        raw_score = sum(f["score"] for f in findings)
        risk_index = min(100.0, raw_score * 3.2)
        if risk_index == 0:
            grade = "A (Hardened)"
        elif risk_index < 25:
            grade = "B (Good Posture)"
        elif risk_index < 50:
            grade = "C (Moderate Exposure)"
        elif risk_index < 75:
            grade = "D (Elevated Risk)"
        else:
            grade = "F (Critical Vulnerabilities)"

        print(f"\n{BOLD}{MAGENTA}[*] STAGE 5: Executive Posture Summary{RESET}")
        print(f"{DIM}─" * 70 + f"{RESET}")
        print(f"  {BOLD}Host Origin           :{RESET} {geo['country']} [{geo['country_code']}] | {geo['city']}")
        print(f"  {BOLD}Host Company / Org    :{RESET} {geo['org']}")
        print(f"  {BOLD}Threat Exposure Index :{RESET} {risk_index:.1f} / 100")
        print(f"  {BOLD}Defensive Grade       :{RESET} {grade}")
        print(f"  {BOLD}Flagged Risk Vectors  :{RESET} {len(findings)}")

        generate_html_report(raw_target, ip, geo, open_ports, findings, risk_index, grade)

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Audit interrupted by operator.{RESET}")
    except Exception as e:
        print(f"\n{RED}[!] Execution halted: {e}{RESET}")
    finally:
        input(f"\n{DIM}Press Enter to exit auditor...{RESET}")

if __name__ == "__main__":
    main()