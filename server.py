# =============================================================================
# PortHive — Multi-Client TCP Echo Server
# Demonstrates: socket.bind / listen / accept / connect, daemon threads
# Author  : Eyad Alsadi  |  University of Petra — 2025/2026
# =============================================================================

import socket
import threading

HOST = "0.0.0.0"   # listen on all available interfaces
PORT = 9999         # port the server will bind to


def handle_client(conn: socket.socket, addr: tuple) -> None:
    """Serve one client — runs inside its own thread."""
    print(f"[+] New connection from {addr}")
    with conn:
        while True:
            data = conn.recv(1024)               # receive up to 1 KB
            if not data:
                break                            # client disconnected
            reply = f"[Echo] {data.decode().strip()}"
            conn.sendall(reply.encode())         # echo the message back
            print(f"    {addr}  →  {data.decode().strip()}")
    print(f"[-] {addr} disconnected")


def main() -> None:
    print("[*] PortHive Echo Server")
    print(f"[*] Binding to {HOST}:{PORT} …\n")

    # Create a TCP socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))                    # bind: attach to address/port
    server.listen(10)                            # listen: queue up to 10 connections

    print(f"[*] Listening on port {PORT}. Press Ctrl+C to stop.\n")

    try:
        while True:
            conn, addr = server.accept()         # accept: block until a client connects

            # Spawn a DAEMON thread for each client (won't block program exit)
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True                      # daemon=True: thread dies with main program
            )
            t.start()
            print(f"[i] Active threads: {threading.active_count() - 1}")

    except KeyboardInterrupt:
        print("\n[!] Server shutting down cleanly.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
