#!/usr/bin/env python3

try:
    import gevent
    from gevent import monkey
    monkey.patch_all()
except ImportError:
    print("[*] Installing gevent for high-performance concurrency...")
    install("gevent")
    import gevent
    from gevent import monkey
    monkey.patch_all()

import argparse
import json
import re
import subprocess
import sys
import time
 
# ── auto-install dependencies ─────────────────────────────────────────────────
 
def install(pkg):
    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "--break-system-packages", "-q"])

try:
    from tqdm import tqdm
except ImportError:
    print("[*] Installing tqdm for progress visualization...")
    install("tqdm")
    from tqdm import tqdm

try:
    import requests
except ImportError:
    print("[*] Installing requests...")
    install("requests")
    import requests
 
try:
    import socks  # noqa: F401
except ImportError:
    print("[*] Installing PySocks for SOCKS proxy support...")
    install("PySocks")
 
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
 
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
 
# ── proxy sources — tagged with protocol ─────────────────────────────────────
 
SOURCES = [
    ("http", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"),
    ("socks4", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt"),
    ("socks5", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"),
    ("http", "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt"),
    ("http", "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt"),
    ("http", "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt"),
    ("http", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"),
    ("socks4", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt"),
    ("socks5", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt"),
    ("http", "https://raw.githubusercontent.com/mertguvencli/http-proxy-list/main/proxy-list/data.txt"),
]
 
# ── get real IP ───────────────────────────────────────────────────────────────
 
def get_real_ip():
    """Get real IP with fallback services."""
    services = [
        "https://api.ipify.org?format=json",
        "https://ifconfig.me/ip",
        "https://icanhazip.com"
    ]
    for url in services:
        try:
            r = requests.get(url, timeout=5, headers=HEADERS)
            if "json" in url:
                return r.json().get("ip")
            return r.text.strip()
        except:
            continue
    return None
 
# ── fetcher ───────────────────────────────────────────────────────────────────
 
def fetch_source(proto, url):
    """Fetch proxies from a source URL and tag them with protocol."""
    try:
        r = requests.get(url, timeout=15, headers=HEADERS, verify=False)
        proxies = []
        for line in r.text.splitlines():
            match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})', line.strip())
            if match:
                proxies.append((proto, f"{match.group(1)}:{match.group(2)}"))
        return proxies
    except Exception:
        return []
 
 
def collect_proxies(count):
    """Collect proxies from all sources with protocol tags."""
    print(f"[*] Fetching from {len(SOURCES)} sources...")
    seen = set()
    all_proxies = []
 
    jobs = [gevent.spawn(fetch_source, proto, url) for proto, url in SOURCES]
    gevent.joinall(jobs, timeout=30)
 
    for job in jobs:
        for proto, proxy in job.value or []:
            if proxy not in seen:
                seen.add(proxy)
                all_proxies.append((proto, proxy))
        print(f"  ... {len(all_proxies)} unique proxies collected so far")
 
    return all_proxies[:count]
 
 
# ── safety checks ─────────────────────────────────────────────────────────────
 
# Multiple verification endpoints for reliability
VERIFY_ENDPOINTS = [
    "http://httpbin.org/ip",
    "http://icanhazip.com",
    "http://ipinfo.io/ip"
]
 
 
def check_ip_leak(proto, proxy, timeout):
    """
    Check if proxy reveals ANY transparency headers.
    Presence of forwarding headers = not anonymous, even if they don't contain your IP.
    """
    try:
        proxy_dict = {proto: f"{proto}://{proxy}"}
        r = requests.get("http://httpbin.org/get", proxies=proxy_dict, timeout=timeout, verify=False, headers=HEADERS)
        headers = {k.lower(): v for k, v in r.json().get("headers", {}).items()}
        
        # ANY of these headers = proxy is transparent
        leak_headers = ["via", "forwarded", "x-forwarded-for", "x-real-ip", "client-ip", "x-originating-ip"]
        found = [h for h in leak_headers if h in headers]
        
        if found:
            return True, f"transparent proxy (headers: {', '.join(found)})"
        return False, "clean"
    except Exception as e:
        return False, f"check failed ({str(e)[:50]})"
 
 
def check_tampering(proto, proxy, timeout):
    """
    Check if proxy injects content into HTML responses.
    Compare direct vs proxied requests to example.com.
    """
    try:
        # Get direct baseline
        direct = requests.get("http://example.com", timeout=timeout, verify=False, headers=HEADERS)
        direct_body = direct.text.lower()
        
        # Get proxied version
        proxy_dict = {proto: f"{proto}://{proxy}"}
        proxied = requests.get("http://example.com", proxies=proxy_dict, timeout=timeout, verify=False, headers=HEADERS)
        proxied_body = proxied.text.lower()
        
        # Check for injected content
        suspicious = ["<script", "<iframe", "advertisement", "doubleclick", "googlesyndication"]
        injected = [s for s in suspicious if s in proxied_body and s not in direct_body]
        
        if injected:
            return True, f"injected content: {', '.join(injected)}"
        
        # Check if structure is drastically different
        if abs(len(proxied_body) - len(direct_body)) > len(direct_body) * 0.5:
            return True, "response size differs by >50%"
        
        return False, "clean"
    except Exception as e:
        return False, f"check failed ({str(e)[:50]})"
 
 
def check_honeypot(proto, proxy, timeout):
    """
    Advanced honeypot detection:
    1. Check if allows loopback connections (very suspicious)
    2. Check if response time is suspiciously fast (<30ms = cached honeypot)
    3. Flag private IP ranges
    """
    flags = []
    
    try:
        ip, port = proxy.rsplit(":", 1)
        port = int(port)
        
        # Check for private/reserved IP ranges
        parts = list(map(int, ip.split(".")))
        if parts[0] in (10, 127) or \
           (parts[0] == 172 and 16 <= parts[1] <= 31) or \
           (parts[0] == 192 and parts[1] == 168):
            return True, "private/reserved IP range"
        
        proxy_dict = {proto: f"{proto}://{proxy}"}
        
        # Test 1: Does it allow loopback connections?
        try:
            r = requests.get("http://127.0.0.1", proxies=proxy_dict, timeout=3, verify=False)
            if r.status_code == 200:
                flags.append("allows loopback")
        except:
            pass
        
        # Test 2: Is response time suspiciously fast?
        start = time.time()
        try:
            requests.get("http://example.com", proxies=proxy_dict, timeout=timeout, verify=False, headers=HEADERS)
            elapsed_ms = (time.time() - start) * 1000
            if elapsed_ms < 30:
                flags.append(f"suspiciously fast ({int(elapsed_ms)}ms)")
        except:
            pass
        
        if flags:
            return True, ", ".join(flags)
        
        # Monitor common honeypot ports (not conclusive, just flagging)
        suspicious_ports = {8080, 3128, 1080, 8888, 9050}
        if port in suspicious_ports:
            return False, f"common port {port} (monitor)"
        
        return False, "clean"
    except Exception as e:
        return False, f"check failed ({str(e)[:50]})"
 
 
def check_ssl_integrity(proto, proxy, timeout):
    """
    Check if proxy performs SSL MITM by validating certificate chain.
    This time we actually verify=True to catch MITM.
    """
    try:
        proxy_dict = {proto: f"{proto}://{proxy}"}
        r = requests.get("https://www.google.com", proxies=proxy_dict, timeout=timeout, verify=True, headers=HEADERS)
        return False, "SSL valid"
    except requests.exceptions.SSLError as e:
        return True, f"SSL certificate invalid (MITM risk)"
    except Exception as e:
        return False, f"check failed ({str(e)[:50]})"
 
 
def get_country(proxyip):
    """Get country code via ip-api.com (free, 45 req/min limit)."""
    try:
        r = requests.get(f"http://ip-api.com/json/{proxyip}?fields=country,countryCode", timeout=5, headers=HEADERS)
        data = r.json()
        return data.get("countryCode", "??")
    except:
        return "??"
 
 
# ── multi-endpoint testing ───────────────────────────────────────────────────
 
def test_proxy(proto, proxy, timeout, real_ip, get_geo=False):
    """
    Test proxy against multiple endpoints for reliability.
    Only consider it working if it passes 2/3 endpoints.
    """
    proxy_dict = {proto: f"{proto}://{proxy}"}
    
    passed_endpoints = 0
    total_time = 0
    
    for url in VERIFY_ENDPOINTS:
        try:
            start = time.time()
            r = requests.get(url, proxies=proxy_dict, timeout=timeout, verify=False, headers=HEADERS)
            elapsed = (time.time() - start) * 1000
            
            if r.status_code == 200:
                passed_endpoints += 1
                total_time += elapsed
        except:
            pass
    
    # Require 2/3 endpoints to pass
    if passed_endpoints < 2:
        return None
    
    avg_latency = int(total_time / passed_endpoints) if passed_endpoints > 0 else 0
    
    # Run safety checks
    ip_leaked, leak_detail = check_ip_leak(proto, proxy, timeout)
    tampered, tamper_detail = check_tampering(proto, proxy, timeout)
    honeypot, honeypot_detail = check_honeypot(proto, proxy, timeout)
    ssl_mitm, ssl_detail = check_ssl_integrity(proto, proxy, timeout)
    
    safe = not (ip_leaked or tampered or honeypot or ssl_mitm)
    
    result = {
        "proxy": proxy,
        "protocol": proto,
        "latency_ms": avg_latency,
        "endpoints_passed": f"{passed_endpoints}/3",
        "safe": safe,
        "ip_leak": ip_leaked,
        "ip_leak_detail": leak_detail,
        "tampered": tampered,
        "tamper_detail": tamper_detail,
        "honeypot": honeypot,
        "honeypot_detail": honeypot_detail,
        "ssl_mitm": ssl_mitm,
        "ssl_detail": ssl_detail,
    }
    
    if get_geo:
        result["country"] = get_country(proxy.split(":")[0])
    
    return result
 
 
# ── display ───────────────────────────────────────────────────────────────────
 
def flag(val):
    return "\033[92mOK\033[0m" if not val else "\033[91mFAIL\033[0m"
 
 
def print_result(r):
    safe_label = "\033[92m[SAFE]\033[0m  " if r["safe"] else "\033[91m[RISK]\033[0m  "
    geo = f" | {r['country']}" if "country" in r else ""
    
    print(
        f"  {safe_label} {r['protocol']:<7} {r['proxy']:<25} {r['latency_ms']}ms ({r['endpoints_passed']}){geo}"
        f"  leak={flag(not r['ip_leak'])}  tamper={flag(not r['tampered'])}  honeypot={flag(not r['honeypot'])}  ssl={flag(not r['ssl_mitm'])}"
    )
    
    if r["ip_leak"]:
        print(f"           \033[91m! IP leak: {r['ip_leak_detail']}\033[0m")
    if r["tampered"]:
        print(f"           \033[91m! Tampering: {r['tamper_detail']}\033[0m")
    if r["honeypot"]:
        print(f"           \033[91m! Honeypot: {r['honeypot_detail']}\033[0m")
    elif "monitor" in r["honeypot_detail"]:
        print(f"           \033[93m~ Note: {r['honeypot_detail']}\033[0m")
    if r["ssl_mitm"]:
        print(f"           \033[91m! SSL/MITM: {r['ssl_detail']}\033[0m")
 
 
# ── main ──────────────────────────────────────────────────────────────────────
 
def main():
    parser = argparse.ArgumentParser(description="Enhanced proxy finder with gevent and multi-endpoint testing")
    parser.add_argument("--count", type=int, default=100, help="Max proxies to test (default 100)")
    parser.add_argument("--workers", type=int, default=100, help="Concurrent gevent workers (default 100)")
    parser.add_argument("--timeout", type=int, default=8, help="Per-proxy timeout seconds (default 8)")
    parser.add_argument("--output", default=None, help="Save working proxies to JSON file")
    parser.add_argument("--safe-only", action="store_true", help="Only output proxies passing all safety checks")
    parser.add_argument("--geo", action="store_true", help="Add country info (slower, rate limited)")
    args = parser.parse_args()
 
    print("[*] Detecting your real IP...")
    real_ip = get_real_ip()
    if real_ip:
        print(f"[*] Real IP: {real_ip} (used for leak detection)")
    else:
        print("[!] Could not detect real IP — IP leak check will be skipped")
 
    candidates = collect_proxies(args.count)
    if not candidates:
        print("[!] Could not fetch any proxies. Check your internet connection.")
        sys.exit(1)
 
    print(f"\n[*] Testing + safety checking {len(candidates)} proxies with {args.workers} workers (gevent)...\n")
    if args.geo:
        print("[!] Geographic lookup enabled — this will be slower due to rate limits\n")
 
    results = []
    done = 0
 
    # Gevent concurrency — much faster than ThreadPoolExecutor
    jobs = [gevent.spawn(test_proxy, proto, proxy, args.timeout, real_ip, args.geo) for proto, proxy in candidates]
    
    with tqdm(total=len(jobs), desc="[*] Testing Proxies", unit="proxy", colour="green") as pbar:
        for job in gevent.iwait(jobs):
            result = job.value
            if result:
                results.append(result)
                status = "[SAFE]" if result["safe"] else "[RISK]"
                pbar.write(f"  {status} {result['protocol']:<7} {result['proxy']}")
       
            pbar.update(1)
 
    results.sort(key=lambda x: (not x["safe"], x["latency_ms"]))
 
    safe = [r for r in results if r["safe"]]
    risky = [r for r in results if not r["safe"]]
    display = safe if args.safe_only else results
 
    print(f"\n{'─'*80}")
    print(f"[*] {len(results)} working  |  {len(safe)} safe  |  {len(risky)} flagged\n")
 
    if display:
        geo_header = "COUNTRY  " if args.geo else ""
        print(f"{'PROTOCOL':<9} {'PROXY':<25} {'LATENCY':<10} {geo_header}{'LEAK':<8} {'TAMPER':<10} {'HONEYPOT':<10} {'SSL/MITM'}")
        print(f"{'─'*9} {'─'*25} {'─'*10} {('─'*9) if args.geo else ''}{'─'*8} {'─'*10} {'─'*10} {'─'*8}")
        for r in display:
            geo_val = f"{r.get('country', '??'):<9}" if args.geo else ""
            print(
                f"{r['protocol']:<9} {r['proxy']:<25} {r['latency_ms']:<10} {geo_val}"
                f"{'YES' if r['ip_leak'] else 'NO':<8} "
                f"{'YES' if r['tampered'] else 'NO':<10} "
                f"{'YES' if r['honeypot'] else 'NO':<10} "
                f"{'YES' if r['ssl_mitm'] else 'NO'}"
            )
 
    if args.output and display:
        with open(args.output, "w") as f:
            json.dump(display, f, indent=2)
        print(f"\n[*] Saved {len(display)} proxies to {args.output}")
 
    if not results:
        print("[!] No working proxies found. Try --count 300 or --timeout 12.")
        sys.exit(1)

    def add_to_proxychains(proxies):
        """Append safe proxies to the [ProxyList] section of proxychains4.conf."""
        import os
        import shutil
        import time

        conf_paths = [
        "/etc/proxychains4.conf",
        "/etc/proxychains.conf",
        ]

        conf = None
        for path in conf_paths:
            if os.path.isfile(path):
                conf = path
                break

        if not conf:
            print("[!] proxychains4.conf not found. Is proxychains4 installed?")
            return

        backup_path = f"{conf}.backup"
        try:
            shutil.copy2(conf, backup_path)
            print(f"[*] Backup created: {backup_path}")
        except Exception as e:
            print(f"[!] Could not create backup: {e}")
            return

        try:
            with open(conf, "r") as f:
                lines = f.readlines()
        except PermissionError:
            print(f"[!] Permission denied reading {conf}. Try running with sudo.")
            return

        insert_at = None
        for i, line in enumerate(lines):
            if line.strip().lower().startswith("[proxylist"):
                insert_at = i + 1
                break

        if insert_at is None:
            print("[!] Could not find [ProxyList] section in proxychains4.conf.")
            return

        existing_proxies = set()
        for line in lines:
            parts = line.strip().split()
            if len(parts) >= 3 and parts[0] in ('http', 'https', 'socks4', 'socks5'):
                existing_proxies.add(f"{parts[1]}:{parts[2]}")

        to_add = []
        for r in proxies:
            host, port = r["proxy"].rsplit(":", 1)
        
            if f"{host}:{port}" in existing_proxies:
                continue
        
            pc_type = "http" if r["protocol"] in ("http", "https") else r["protocol"]
            to_add.append(f"{pc_type} {host} {port}\n")

        if not to_add:
            print("[*] All proxies already in proxychains4.conf — nothing to add.")
            return

        header = [
            f"\n# Added by proxyfinder on {time.strftime('%Y-%m-%d %H:%M:%S')}\n",
            f"# {len(to_add)} safe proxies\n"
        ]
        lines = lines[:insert_at] + header + to_add + lines[insert_at:]

        try:
            with open(conf, "w") as f:
                f.writelines(lines)
            print(f"[+] Added {len(to_add)} proxies to {conf}")
            print("[*] Test with: proxychains4 curl https://api.ipify.org")
        except PermissionError:
            print(f"[!] Permission denied writing {conf}. Try running with sudo.")
 
 
if __name__ == "__main__":
    main()