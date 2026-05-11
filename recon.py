# =============================================================================
# PortHive v2.0 — Reconnaissance Module
# Author  : Eyad Alsadi  |  ID: 202211140
# Course  : Information & Network Security Programming (605346)
# Instructor: Dr. Mohammad Arafah  |  University of Petra — 2025/2026
# ETHICS: For authorized lab/educational use ONLY. Do NOT use against
#         systems you do not own or have explicit written permission to test.
# =============================================================================

import socket
import threading
import urllib.request
import subprocess
import os
from datetime import datetime

# ── Common subdomain wordlist ─────────────────────────────────────────────────
SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev",
    "test", "vpn", "remote", "blog", "shop", "portal"
]

# ── Thread-safe lock (same pattern as Phase 1) ────────────────────────────────
_lock = threading.Lock()


def dns_lookup(target: str) -> list:
    """Technique 1 — DNS enumeration: resolve all IPs for a hostname."""
    try:
        results = socket.getaddrinfo(target, None)
        return list(set(r[4][0] for r in results))   # deduplicate IPs
    except socket.gaierror as e:
        return [f"DNS error: {e}"]


def banner_grab(host: str, port: int) -> str:
    """Technique 2 — Banner grabbing: connect and read the service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")        # generic probe
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner[:150] if banner else "(no banner)"
    except Exception:
        return "(no response)"


def http_headers(target: str) -> dict:
    """Technique 3 — HTTP header inspection via urllib (no external libs)."""
    url = target if target.startswith("http") else f"http://{target}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PortHive/2.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return dict(resp.headers)
    except Exception as e:
        return {"error": str(e)}


def whois_lookup(target: str) -> str:
    """Technique 4 — WHOIS: tries system command, falls back to raw socket."""
    # Try system whois first (Linux/Mac)
    try:
        r = subprocess.run(
            ["whois", target], capture_output=True, text=True, timeout=8
        )
        if r.stdout:
            return r.stdout[:400]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: raw TCP query to whois.iana.org port 43
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(6)
        sock.connect(("whois.iana.org", 43))
        sock.send(f"{target}\r\n".encode())
        data = b""
        while chunk := sock.recv(4096):
            data += chunk
        sock.close()
        return data.decode(errors="ignore")[:400]
    except Exception as e:
        return f"WHOIS unavailable: {e}"


def subdomain_bruteforce(domain: str, log_file: str) -> list:
    """Technique 5 — Subdomain brute-force using threading (Phase 1 pattern)."""
    found = []

    def check(sub):
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            msg = f"    [FOUND] {fqdn}  →  {ip}"
            print(msg)
            with _lock:                           # thread-safe write
                with open(log_file, "a") as f:
                    f.write(msg + "\n")
            found.append(fqdn)
        except socket.gaierror:
            pass                                  # subdomain does not exist

    threads = [threading.Thread(target=check, args=(s,), daemon=True)
               for s in SUBDOMAINS]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return found


def run_recon(target: str) -> str:
    """Run all five reconnaissance techniques and save a structured report."""
    os.makedirs("recon_results", exist_ok=True)
    stamp    = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join("recon_results", f"recon_{target}_{stamp}.txt")

    def log(msg: str):
        print(msg)
        with _lock:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(msg + "\n")

    log("=" * 60)
    log(f"  PortHive Recon Report  |  {datetime.now():%Y-%m-%d %H:%M:%S}")
    log(f"  Target : {target}")
    log("=" * 60)

    # 1. DNS
    log("\n[1] DNS Enumeration")
    for ip in dns_lookup(target):
        log(f"    {target}  →  {ip}")

    # 2. Banner grabbing on common ports
    log("\n[2] Banner Grabbing")
    for port in [21, 22, 25, 80, 443, 8080]:
        b = banner_grab(target, port)
        if b != "(no response)":
            log(f"    Port {port}: {b[:80]}")

    # 3. HTTP headers
    log("\n[3] HTTP Header Inspection")
    for k, v in list(http_headers(target).items())[:6]:
        log(f"    {k}: {v}")

    # 4. WHOIS
    log("\n[4] WHOIS Lookup")
    for line in whois_lookup(target).splitlines()[:8]:
        log(f"    {line}")

    # 5. Subdomain brute-force
    log("\n[5] Subdomain Brute-Force")
    found = subdomain_bruteforce(target, log_file)
    if not found:
        log("    No subdomains resolved.")

    log(f"\n[+] Report saved  →  {log_file}")
    return log_file


# ── CLI entry point ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="PortHive — Recon Module")
    parser.add_argument("-t", "--target", required=True,
                        help="Target domain or IP (authorized hosts only)")
    run_recon(parser.parse_args().target)
