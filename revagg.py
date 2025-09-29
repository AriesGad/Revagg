#!/usr/bin/env python3
"""
revagg.py - Reverse-IP / hostname aggregator + colored HTTP probe (Termux-friendly, no-root)

Usage:
  python3 revagg.py <ip-or-domain> [--ports 80,443,8080] [--workers 20] [--timeout 8]

Outputs:
  revagg_candidates.txt  - deduped hostnames
  revagg_live.txt        - CSV of live hits (Method,Code,Server,Port,IP,Host)
  revagg_debug.log       - debug / source details

Notes:
 - Uses PTR, hackertarget, viewdns.info, crt.sh (when domain given).
 - Built-in HTTP probe checks ports you pass (default: 80,443,8080,8443).
 - Colored table output (requires colorama).
 - Only test targets you own or have explicit permission to test.
"""

import sys
import socket
import requests
import time
import json
import re
import dns.resolver
import dns.reversename
from bs4 import BeautifulSoup
import concurrent.futures
import functools
import traceback
import argparse
from colorama import init as colorama_init, Fore, Style
import urllib3
from urllib.parse import urlparse

# disable insecure request warnings shown when verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ======== Configuration (defaults) ========
DEFAULT_PORTS = [80, 443, 8080, 8443]
TIMEOUT = 8
SLEEP_BETWEEN_QUERIES = 1.0
USER_AGENT = "revagg/1.2 (Termux) - polite-recon"
HEADERS = {"User-Agent": USER_AGENT}
DEBUG_LOG = "revagg_debug.log"
CAND_FILE = "revagg_candidates.txt"
LIVE_FILE = "revagg_live.txt"

HACKERTARGET_URL = "https://api.hackertarget.com/reverseiplookup/?q={ip}"
VIEWDNS_URL = "https://viewdns.info/reverseip/?host={ip}&t=1"
CRTSH_URL = "https://crt.sh/?q={query}&output=json"
RAPIDDNS_URL = "https://rapiddns.io/sameip/{ip}"
THREATCROWD_URL = "https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={ip}"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
COMMONCRAWL_COLLINFO = "https://index.commoncrawl.org/collinfo.json"
COMMONCRAWL_URL = "{index_url}?url=*.{domain}/&output=json&fl=url&limit=10000"  # limit to avoid too many
WAYBACK_URL = "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=10000"

# concurrency default
DEFAULT_WORKERS = 20

# ASCII banner
BANNER = r"""
  ____  _____ ____   ___    _    ____   ____  ____  
 |  _ \| ____|  _ \ / _ \  / \  / ___| / ___||  _ \ 
 | |_) |  _| | |_) | | | |/ _ \ \___ \ \___ \| |_) |
 |  _ <| |___|  _ <| |_| / ___ \ ___) | ___) |  __/ 
 |_| \_\_____|_| \_\\___/_/   \_\____/ |____/|_|    
                                                   
 Reverse-IP aggregator + HTTP probe (revagg)
"""

# init colorama
colorama_init(autoreset=True)

# ======== Utility logging ========
def dbg(msg):
    with open(DEBUG_LOG, "a") as f:
        f.write(f"{time.asctime()}: {msg}\n")

# ======== DNS / Aggregation functions ========
def ptr_lookup(ip):
    hosts = set()
    try:
        name = socket.gethostbyaddr(ip)[0]
        hosts.add(name)
        dbg(f"PTR socket: {ip} -> {name}")
    except Exception as e:
        dbg(f"PTR socket failed for {ip}: {e}")
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev_name, "PTR", lifetime=5)
            for a in answers:
                hosts.add(str(a).rstrip("."))
            dbg(f"PTR dnspython: {ip} -> {hosts}")
        except Exception as e2:
            dbg(f"PTR dnspython failed for {ip}: {e2}")
    return hosts

def query_hackertarget(ip):
    results = set()
    try:
        url = HACKERTARGET_URL.format(ip=ip)
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200 and "No records" not in r.text:
            for line in r.text.splitlines():
                line = line.strip()
                if line and not line.startswith("error"):
                    results.add(line)
        else:
            dbg(f"hackertarget returned status {r.status_code} for {ip}")
    except Exception as e:
        dbg(f"hackertarget error for {ip}: {e}")
    return results

def query_viewdns(ip):
    results = set()
    try:
        url = VIEWDNS_URL.format(ip=ip)
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            table = soup.find("table", attrs={"border": "1"})
            if table:
                rows = table.find_all("tr")
                for row in rows[1:]:
                    cols = row.find_all("td")
                    if len(cols) >= 1:
                        hostname = cols[0].get_text(strip=True)
                        if hostname and hostname != "-" and hostname.lower() != "host":
                            results.add(hostname)
            else:
                dbg(f"viewdns: table not found for {ip}")
        else:
            dbg(f"viewdns returned status {r.status_code} for {ip}")
    except Exception as e:
        dbg(f"viewdns error for {ip}: {e}")
    return results

def query_rapiddns(ip):
    results = set()
    try:
        url = RAPIDDNS_URL.format(ip=ip)
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            table = soup.find("table", id="table")
            if table:
                rows = table.find_all("tr")
                for row in rows[1:]:
                    cols = row.find_all("td")
                    if len(cols) >= 1:
                        hostname = cols[0].get_text(strip=True)
                        if hostname:
                            results.add(hostname)
            else:
                dbg(f"rapiddns: table not found for {ip}")
        else:
            dbg(f"rapiddns returned status {r.status_code} for {ip}")
    except Exception as e:
        dbg(f"rapiddns error for {ip}: {e}")
    return results

def query_threatcrowd(ip):
    results = set()
    try:
        url = THREATCROWD_URL.format(ip=ip)
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            if data.get("response_code") == "1":
                for res in data.get("resolutions", []):
                    domain = res.get("domain")
                    if domain:
                        results.add(domain)
        else:
            dbg(f"threatcrowd returned status {r.status_code} for {ip}")
    except Exception as e:
        dbg(f"threatcrowd error for {ip}: {e}")
    return results

def query_crtsh_for_domain(domain):
    results = set()
    try:
        q = f"%25.{domain}"
        url = CRTSH_URL.format(query=q)
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            try:
                data = r.json()
                for item in data:
                    name = item.get("name_value")
                    if name:
                        for n in re.split(r"\s+", name):
                            n = n.strip().rstrip(".")
                            if n:
                                results.add(n)
            except Exception as e:
                dbg(f"crt.sh parse error for {domain}: {e}")
        else:
            dbg(f"crt.sh returned status {r.status_code} for {domain}")
    except Exception as e:
        dbg(f"crt.sh error for {domain}: {e}")
    return results

def query_certspotter_for_domain(domain):
    results = set()
    try:
        url = CERTSPOTTER_URL.format(domain=domain)
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            for item in data:
                dns_names = item.get("dns_names", [])
                for name in dns_names:
                    name = name.strip().rstrip(".")
                    if name:
                        results.add(name)
        else:
            dbg(f"certspotter returned status {r.status_code} for {domain}")
    except Exception as e:
        dbg(f"certspotter error for {domain}: {e}")
    return results

def get_latest_commoncrawl_index():
    try:
        r = requests.get(COMMONCRAWL_COLLINFO, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            if data:
                return data[0]["cdx_api"]  # latest
    except Exception as e:
        dbg(f"commoncrawl collinfo error: {e}")
    return None

def query_commoncrawl_for_domain(domain):
    results = set()
    index_url = get_latest_commoncrawl_index()
    if not index_url:
        return results
    try:
        url = COMMONCRAWL_URL.format(index_url=index_url, domain=domain)
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            lines = r.text.splitlines()
            for line in lines:
                if line.strip():
                    data = json.loads(line)
                    if "url" in data:
                        parsed = urlparse(data["url"])
                        if parsed.hostname:
                            results.add(parsed.hostname)
        else:
            dbg(f"commoncrawl returned status {r.status_code} for {domain}")
    except Exception as e:
        dbg(f"commoncrawl error for {domain}: {e}")
    return results

def query_wayback_for_domain(domain):
    results = set()
    try:
        url = WAYBACK_URL.format(domain=domain)
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            for item in data[1:]:  # skip header
                if item:
                    parsed = urlparse(item[0])
                    if parsed.hostname:
                        results.add(parsed.hostname)
        else:
            dbg(f"wayback returned status {r.status_code} for {domain}")
    except Exception as e:
        dbg(f"wayback error for {domain}: {e}")
    return results

# ======== HTTP probe ========
def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return "0.0.0.0"

def probe_one(host, port, timeout=8):
    """
    Probe host:port with GET, return dict or None.
    """
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout, verify=False, allow_redirects=True)
        code = r.status_code
        server = r.headers.get("Server", "") or r.headers.get("server", "")
        ip = resolve_ip(host)
        return {
            "Method": "GET",
            "Code": str(code),
            "Server": server,
            "Port": str(port),
            "IP": ip,
            "Host": host
        }
    except requests.exceptions.SSLError as e:
        dbg(f"SSL error for {host}:{port} - {e}")
        return None
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None
    except Exception as e:
        dbg(f"probe error {host}:{port} - {e}\n{traceback.format_exc()}")
        return None

def bulk_probe(hosts, ports, max_workers=DEFAULT_WORKERS, timeout=8):
    """
    Concurrently probe hosts x ports. Returns list of result dicts.
    """
    results = []
    tasks = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for h in hosts:
            for p in ports:
                tasks.append(ex.submit(probe_one, h, p, timeout))
        for fut in concurrent.futures.as_completed(tasks):
            try:
                r = fut.result()
            except Exception as e:
                dbg(f"task exception: {e}")
                r = None
            if r:
                results.append(r)
    return results

# ======== Formatting & output (colored) ========
def truncate_server(s, width=20):
    s = (s or "").strip()
    if len(s) <= width:
        return s
    return s[: width - 1] + "…"

def color_for_code(code_str):
    try:
        code = int(code_str)
    except Exception:
        return Fore.WHITE
    if 200 <= code < 300:
        return Fore.GREEN
    if 300 <= code < 400:
        return Fore.CYAN
    if 400 <= code < 500:
        return Fore.YELLOW
    if 500 <= code < 600:
        return Fore.RED
    return Fore.WHITE

def print_table(rows):
    # columns: Method Code Server Port IP Host
    hdr = f"{'Method':<6}  {'Code':<4}  {'Server':<20}  {'Port':>5}  {'IP':<15}  {'Host'}"
    sep = f"{'-'*6}  {'-'*4}  {'-'*20}  {'-'*5}  {'-'*15}  {'-'*30}"
    print(Fore.MAGENTA + hdr + Style.RESET_ALL)
    print(Fore.MAGENTA + sep + Style.RESET_ALL)
    for r in rows:
        server = truncate_server(r.get("Server", ""), 20)
        host = r.get("Host", "")
        code = r.get("Code", "")
        color = color_for_code(code)
        line = f"{r.get('Method',''):<6}  {code:<4}  {server:<20}  {r.get('Port',''):>5}  {r.get('IP',''):<15}  {host}"
        print(color + line + Style.RESET_ALL)

def save_live_rows(rows, out_file=LIVE_FILE):
    # save CSV lines for parsing
    with open(out_file, "w") as f:
        f.write("Method,Code,Server,Port,IP,Host\n")
        for r in rows:
            server = (r.get("Server","") or "").replace(",", " ")
            line = f"{r.get('Method','')},{r.get('Code','')},{server},{r.get('Port','')},{r.get('IP','')},{r.get('Host','')}\n"
            f.write(line)

# ======== Main logic ========
def parse_ports(ports_arg):
    if not ports_arg:
        return DEFAULT_PORTS
    # accept comma-separated list, allow spaces
    try:
        parts = re.split(r"[,\s]+", ports_arg.strip())
        ports = [int(p) for p in parts if p]
        return ports
    except Exception:
        dbg(f"invalid ports argument: {ports_arg}")
        return DEFAULT_PORTS

def main():
    parser = argparse.ArgumentParser(description="revagg - reverse IP aggregator + HTTP probe (Termux)")
    parser.add_argument("target", help="IP or domain to investigate")
    parser.add_argument("--ports", "-p", help="Comma-separated ports to probe (default: 80,443,8080,8443)")
    parser.add_argument("--workers", "-w", type=int, default=DEFAULT_WORKERS, help=f"Number of concurrent workers (default: {DEFAULT_WORKERS})")
    parser.add_argument("--timeout", "-t", type=int, default=TIMEOUT, help=f"HTTP timeout seconds (default: {TIMEOUT})")
    args = parser.parse_args()

    target = args.target
    ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS
    workers = args.workers
    timeout = args.timeout

    print(BANNER)
    dbg(f"=== Start scan for: {target} (ports={ports} workers={workers} timeout={timeout}) ===")
    ips = set()
    domain = None
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", target):
        ips.add(target)
    else:
        domain = target
        try:
            answers = dns.resolver.resolve(domain, "A", lifetime=5)
            for a in answers:
                ips.add(a.to_text())
            dbg(f"Resolved domain {domain} -> {ips}")
        except Exception as e:
            dbg(f"DNS A resolution failed for {domain}: {e}")
            try:
                ip = socket.gethostbyname(domain)
                ips.add(ip)
                dbg(f"socket resolved {domain} -> {ip}")
            except Exception as e2:
                dbg(f"socket resolution failed for {domain}: {e2}")

    if not ips:
        print("No IPs found for target; exiting.")
        return

    all_candidates = set()
    sources = []

    for ip in ips:
        print(f"[+] Inspecting IP: {ip}")
        ptrs = ptr_lookup(ip)
        if ptrs:
            print(f"  PTR: {', '.join(ptrs)}")
            all_candidates.update(ptrs)
            sources.append(("PTR", ip, ptrs))
        time.sleep(SLEEP_BETWEEN_QUERIES)

        print("  Querying hackertarget...")
        ht = query_hackertarget(ip)
        if ht:
            print(f"  hackertarget: {len(ht)} results")
            all_candidates.update(ht)
            sources.append(("hackertarget", ip, ht))
        else:
            print("  hackertarget: no results or rate-limited")
        time.sleep(SLEEP_BETWEEN_QUERIES)

        print("  Querying viewdns.info (scrape)...")
        vd = query_viewdns(ip)
        if vd:
            print(f"  viewdns: {len(vd)} results")
            all_candidates.update(vd)
            sources.append(("viewdns", ip, vd))
        else:
            print("  viewdns: no results or rate-limited")
        time.sleep(SLEEP_BETWEEN_QUERIES)

        print("  Querying rapiddns (scrape)...")
        rd = query_rapiddns(ip)
        if rd:
            print(f"  rapiddns: {len(rd)} results")
            all_candidates.update(rd)
            sources.append(("rapiddns", ip, rd))
        else:
            print("  rapiddns: no results or rate-limited")
        time.sleep(SLEEP_BETWEEN_QUERIES)

        print("  Querying threatcrowd...")
        tc = query_threatcrowd(ip)
        if tc:
            print(f"  threatcrowd: {len(tc)} results")
            all_candidates.update(tc)
            sources.append(("threatcrowd", ip, tc))
        else:
            print("  threatcrowd: no results or rate-limited")
        time.sleep(SLEEP_BETWEEN_QUERIES)

    if domain:
        print("  Querying crt.sh for certificate transparency entries (may be large)...")
        crt = query_crtsh_for_domain(domain)
        if crt:
            print(f"  crt.sh: {len(crt)} results")
            all_candidates.update(crt)
            sources.append(("crt.sh", domain, crt))
        else:
            print("  crt.sh: no results or rate-limited")
        time.sleep(SLEEP_BETWEEN_QUERIES)

        print("  Querying certspotter for certificate transparency entries...")
        cs = query_certspotter_for_domain(domain)
        if cs:
            print(f"  certspotter: {len(cs)} results")
            all_candidates.update(cs)
            sources.append(("certspotter", domain, cs))
        else:
            print("  certspotter: no results or rate-limited")
        time.sleep(SLEEP_BETWEEN_QUERIES)

        print("  Querying commoncrawl for archived entries...")
        cc = query_commoncrawl_for_domain(domain)
        if cc:
            print(f"  commoncrawl: {len(cc)} results")
            all_candidates.update(cc)
            sources.append(("commoncrawl", domain, cc))
        else:
            print("  commoncrawl: no results or rate-limited")
        time.sleep(SLEEP_BETWEEN_QUERIES)

        print("  Querying wayback archive for archived entries...")
        wb = query_wayback_for_domain(domain)
        if wb:
            print(f"  wayback: {len(wb)} results")
            all_candidates.update(wb)
            sources.append(("wayback", domain, wb))
        else:
            print("  wayback: no results or rate-limited")
        time.sleep(SLEEP_BETWEEN_QUERIES)

    # Write candidates
    with open(CAND_FILE, "w") as f:
        for h in sorted(all_candidates):
            f.write(h + "\n")

    print(f"\n[+] Aggregation complete. {len(all_candidates)} unique candidates written to {CAND_FILE}")
    dbg(f"Sources: {json.dumps([(s[0], s[1], len(s[2])) for s in sources])}")

    if not all_candidates:
        print("[*] No candidate hosts to probe. Exiting.")
        return

    # HTTP probing
    print("\n[*] Starting HTTP/HTTPS probes on candidate hosts (ports: {})".format(", ".join(map(str, ports))))
    candidates_list = sorted(all_candidates)

    rows = bulk_probe(candidates_list, ports=ports, max_workers=workers, timeout=timeout)

    # sort rows by Host then Port
    rows_sorted = sorted(rows, key=lambda x: (x.get("Host",""), int(x.get("Port","0"))))

    # colored table to stdout
    print()
    print_table(rows_sorted)

    # save CSV-like file for easy parsing
    save_live_rows(rows_sorted, LIVE_FILE)
    print(f"\n[+] Live hits saved to {LIVE_FILE} (CSV rows).")
    print("Done. See revagg_debug.log for internal notes.")
    dbg("=== End scan ===\n")

if __name__ == "__main__":
    main()