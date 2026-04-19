# PortHive

> Multi-threaded Network Port Scanner  
> Author: Eyad Alsadi (202211140) — University of Petra, 2025/2026  
> Course: Information & Network Security Programming (605346)

---

## What is PortHive?

PortHive is a Python command-line tool that scans one or more hosts for open TCP/UDP ports using a pool of concurrent threads. Like bees in a hive, each thread independently investigates its assigned port and reports back to the central log.

---

## Files

| File | Description |
|------|-------------|
| `porthive.py` | Main port scanner (run this) |
| `server.py`   | Multi-client TCP echo server (demo) |

---

## Requirements

- Python 3.8 or newer
- No external packages needed (standard library only)

---

## Usage — Port Scanner

```bash
python porthive.py -t <target> -p <port-range> -T <threads> [--udp]
```

### Arguments

| Flag | Description | Example |
|------|-------------|---------|
| `-t` | Target host(s), comma-separated | `192.168.1.1` |
| `-p` | Port range | `1-1024` |
| `-T` | Number of threads (default: 100) | `200` |
| `--udp` | Also scan UDP ports | _(flag only)_ |

### Examples

```bash
# Scan common ports on a single host
python porthive.py -t 192.168.1.1 -p 1-1024

# Scan multiple hosts with 200 threads
python porthive.py -t scanme.nmap.org -p 1-500 -T 200

# Include UDP scan
python porthive.py -t 10.0.0.1 -p 1-100 --udp
```

---

## Usage — Echo Server

```bash
python server.py
```

The server binds to port **9999** and accepts multiple clients simultaneously. Test it with:

```bash
# In a second terminal:
nc 127.0.0.1 9999
```

Type any message and the server will echo it back.

---

## Log Files

All scan results are saved inside a `logs/` folder:

```
logs/
├── scan_20251015_143022.log      ← main result file
└── archive_20251015_143022.log   ← shutil backup copy
```

Each log entry includes timestamp, thread name, protocol, host, port, and status.

---

## Design Highlights

- **ThreadPoolExecutor** manages the worker thread pool (no manual thread lifecycle)
- **threading.Lock** prevents race conditions on the shared log file
- **Daemon threads** in the server auto-terminate when the main process exits
- **os.makedirs** creates the logs folder if it does not exist
- **shutil.copy** archives the completed scan log automatically

---

## GitHub Repository

> [https://github.com/eyadalsadiii/porthive](https://github.com/eyadalsadiii/porthive)

_Replace with your actual GitHub link before submitting._
