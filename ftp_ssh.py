# =============================================================================
# PortHive v2.0 — FTP / SSH Interaction Module
# Author  : Eyad Alsadi  |  ID: 202211140
# Course  : Information & Network Security Programming (605346)
# Instructor: Dr. Mohammad Arafah  |  University of Petra — 2025/2026
# ETHICS: For authorized lab/educational use ONLY.
# =============================================================================

import ftplib
import paramiko
import threading
import time
import os

# ── Rate-Limiter: prevents brute-force bursts ─────────────────────────────────
class RateLimiter:
    """Allow max MAX_ATTEMPTS connections per WINDOW_SEC seconds."""
    MAX_ATTEMPTS = 5
    WINDOW_SEC   = 60

    def __init__(self):
        self._count = 0
        self._window_start = time.time()
        self._lock = threading.Lock()

    def check(self) -> bool:
        """Return True if attempt is allowed; False (+ sleep) if rate-limited."""
        with self._lock:
            now = time.time()
            if now - self._window_start > self.WINDOW_SEC:
                self._count = 0                    # reset window
                self._window_start = now
            self._count += 1
            if self._count > self.MAX_ATTEMPTS:
                print(f"[!] Rate limit hit — sleeping {self.WINDOW_SEC}s …")
                time.sleep(self.WINDOW_SEC)
                self._count = 0
                self._window_start = time.time()
                return False
            return True


_rate = RateLimiter()   # shared rate-limiter instance


# ═══════════════════════════════  FTP  ═══════════════════════════════════════

def ftp_connect(host: str, port: int = 21,
                user: str = "anonymous", password: str = "") -> ftplib.FTP | None:
    """Connect and authenticate to an FTP server."""
    if not _rate.check():
        return None
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, 2121, timeout=6)
        ftp.login(user, password)
        print(f"[+] FTP  connected  :  {user}@{host}:{port}")
        print(f"    Welcome msg     :  {ftp.getwelcome()}")
        return ftp
    except ftplib.all_errors as e:
        print(f"[-] FTP error: {e}")
        return None


def ftp_list(ftp: ftplib.FTP) -> list:
    """List files in the current FTP directory."""
    try:
        files = ftp.nlst()
        print(f"[+] FTP directory listing  ({len(files)} items):")
        for f in files:
            print(f"    {f}")
        return files
    except ftplib.all_errors as e:
        print(f"[-] FTP list error: {e}")
        return []


def ftp_upload(ftp: ftplib.FTP, local_path: str, remote_name: str) -> None:
    """Upload a local file to the FTP server (STOR command)."""
    try:
        with open(local_path, "rb") as f:
            ftp.storbinary(f"STOR {remote_name}", f)
        print(f"[+] FTP uploaded  :  {local_path}  →  {remote_name}")
    except Exception as e:
        print(f"[-] FTP upload error: {e}")


# ═══════════════════════════════  SSH  ═══════════════════════════════════════

def ssh_connect(host: str, port: int = 22, user: str = "root",
                password: str = None, key_path: str = None) -> paramiko.SSHClient | None:
    """Open an SSH session using password auth OR RSA key-based auth."""
    if not _rate.check():
        return None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if key_path:                                 # key-based auth (preferred)
            key = paramiko.RSAKey.from_private_key_file(key_path)
            client.connect(host, port=port, username=user, pkey=key, timeout=6)
            print(f"[+] SSH  connected (key auth)  :  {user}@{host}:{port}")
        else:                                        # password auth (fallback)
            client.connect(host, port=port, username=user,
                           password=password, timeout=6)
            print(f"[+] SSH  connected (pwd auth)  :  {user}@{host}:{port}")

        return client
    except Exception as e:
        print(f"[-] SSH error: {e}")
        return None


def ssh_execute(client: paramiko.SSHClient, command: str) -> str:
    """Run a single command on the remote SSH host and return its output."""
    try:
        _, stdout, stderr = client.exec_command(command)
        out = stdout.read().decode(errors="ignore").strip()
        err = stderr.read().decode(errors="ignore").strip()
        print(f"[+] SSH exec  »  {command}")
        print(f"    stdout : {out[:200]}")
        if err:
            print(f"    stderr : {err[:100]}")
        return out
    except Exception as e:
        print(f"[-] SSH exec error: {e}")
        return ""


def sftp_transfer(client: paramiko.SSHClient,
                  local_path: str, remote_path: str) -> None:
    """Transfer a file to the remote host via SFTP (encrypted)."""
    try:
        sftp = client.open_sftp()                   # open SFTP sub-system
        sftp.put(local_path, remote_path)
        sftp.close()
        print(f"[+] SFTP  upload  :  {local_path}  →  {remote_path}")
    except Exception as e:
        print(f"[-] SFTP error: {e}")


# ── CLI entry point ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="PortHive — FTP/SSH Module")
    parser.add_argument("--host",     required=True, help="Target host")
    parser.add_argument("--proto",    choices=["ftp", "ssh"], required=True)
    parser.add_argument("--user",     default="anonymous")
    parser.add_argument("--password", default="")
    parser.add_argument("--key",      help="Path to RSA private key (SSH only)")
    parser.add_argument("--cmd",      help="Command to execute (SSH only)")
    parser.add_argument("--upload",   help="Local file path to upload")
    parser.add_argument("--remote",   help="Remote destination path")
    args = parser.parse_args()

    if args.proto == "ftp":
        ftp = ftp_connect(args.host, user=args.user, password=args.password)
        if ftp:
            ftp_list(ftp)
            if args.upload and args.remote:
                ftp_upload(ftp, args.upload, args.remote)
            ftp.close()

    elif args.proto == "ssh":
        ssh = ssh_connect(args.host, user=args.user,
                          password=args.password or None, key_path=args.key)
        if ssh:
            if args.cmd:
                ssh_execute(ssh, args.cmd)
            if args.upload and args.remote:
                sftp_transfer(ssh, args.upload, args.remote)
            ssh.close()
