# =============================================================================
# PortHive v1.0 — Multi-threaded Network Port Scanner
# Author  : Eyad Alsadi  |  ID: 202211140
# Course  : Information & Network Security Programming (605346)
# Instructor: Dr. Mohammad Arafah  |  University of Petra — 2025/2026
# =============================================================================

import argparse
import socket
import threading
import os
import shutil
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# ── ASCII Banner ──────────────────────────────────────────────────────────────
BANNER = r"""
  ____            _   _   _ _
 |  _ \ ___  _ __| |_| | | (_)_   _____
 | |_) / _ \| '__| __| |_| | \ \ / / _ \
 |  __/ (_) | |  | |_|  _  | |\ V /  __/
 |_|   \___/|_|   \__|_| |_|_| \_/ \___|

  PortHive v1.0  —  Multi-threaded Port Scanner
  Author  : Eyad Alsadi (202211140)
  Course  : Information & Network Security Programming
"""

# ── Thread-safe lock (prevents race conditions when writing to the log file) ──
_log_lock = threading.Lock()


def log(filepath: str, message: str) -> None:
    """Append a line to the log file.  Lock ensures only one thread writes at a time."""
    with _log_lock:                              # acquire lock → write → release
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(message + "\n")


def scan_tcp(host: str, port: int, log_file: str) -> None:
    """Attempt a TCP connection to host:port and record the result."""
    tid = threading.current_thread().name        # include thread name in log
    ts  = datetime.now().strftime("%H:%M:%S")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((host, port))   # 0 = success (port is OPEN)
        sock.close()
        status = "OPEN" if result == 0 else "CLOSED"
    except Exception:
        status = "ERROR"

    if status == "OPEN":                         # only print/log open ports
        msg = f"[{ts}] [{tid}] TCP  {host}:{port:<5}  →  {status}"
        print(msg)
        log(log_file, msg)


def scan_udp(host: str, port: int, log_file: str) -> None:
    """Send an empty UDP datagram and infer port status from the response."""
    tid = threading.current_thread().name
    ts  = datetime.now().strftime("%H:%M:%S")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)
        sock.sendto(b"", (host, port))
        sock.recvfrom(1024)
        sock.close()
        status = "OPEN"
    except socket.timeout:
        status = "OPEN|FILTERED"                 # no reply ≠ definitely closed
    except Exception:
        status = "CLOSED"

    if "OPEN" in status:
        msg = f"[{ts}] [{tid}] UDP  {host}:{port:<5}  →  {status}"
        print(msg)
        log(log_file, msg)


def main() -> None:
    print(BANNER)

    # ── Argument parser ───────────────────────────────────────────────────────
    parser = argparse.ArgumentParser(
        prog="porthive",
        description="PortHive — Multi-threaded Port Scanner"
    )
    parser.add_argument("-t", "--target",  required=True,
                        help='Target host(s), comma-separated  e.g. 192.168.1.1,192.168.1.2')
    parser.add_argument("-p", "--ports",   default="1-1024",
                        help='Port range  e.g. 1-1024  (default: 1-1024)')
    parser.add_argument("-T", "--threads", type=int, default=100,
                        help='Thread-pool size  (default: 100)')
    parser.add_argument("--udp",           action="store_true",
                        help='Also run UDP scan alongside TCP')
    args = parser.parse_args()

    # ── Parse targets & ports ─────────────────────────────────────────────────
    targets    = [t.strip() for t in args.target.split(",")]
    start, end = map(int, args.ports.split("-"))
    ports      = range(start, end + 1)

    # ── Prepare log directory & file (uses os + shutil) ──────────────────────
    log_dir   = "logs"
    os.makedirs(log_dir, exist_ok=True)          # os.makedirs: create /logs folder
    stamp     = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file  = os.path.join(log_dir, f"scan_{stamp}.log")

    # ── Write scan header to log ──────────────────────────────────────────────
    log(log_file, "=" * 60)
    log(log_file, f"  PortHive Scan  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(log_file, f"  Targets  : {', '.join(targets)}")
    log(log_file, f"  Ports    : {args.ports}   Threads: {args.threads}")
    log(log_file, "=" * 60)

    print(f"[*] Targets  : {', '.join(targets)}")
    print(f"[*] Ports    : {args.ports}")
    print(f"[*] Threads  : {args.threads}")
    print(f"[*] Log file : {log_file}\n")

    # ── Concurrent scanning via ThreadPoolExecutor ────────────────────────────
    protos = ["tcp", "udp"] if args.udp else ["tcp"]

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        for proto in protos:
            for host in targets:
                for port in ports:
                    # Each port scan is submitted as an independent task
                    if proto == "tcp":
                        pool.submit(scan_tcp, host, port, log_file)
                    else:
                        pool.submit(scan_udp, host, port, log_file)
    # ThreadPoolExecutor.__exit__ waits for ALL tasks before continuing

    # ── Archive the completed log with shutil ─────────────────────────────────
    archive = os.path.join(log_dir, f"archive_{stamp}.log")
    shutil.copy(log_file, archive)               # shutil.copy: backup of scan results

    log(log_file, "\n[+] Scan finished.")
    print(f"\n[+] Scan complete.   Results  →  {log_file}")
    print(f"[+] Archive copy  →  {archive}")


if __name__ == "__main__":
    main()
