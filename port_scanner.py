#!/usr/bin/env python3
"""
Port Scanner - A simple but functional TCP/UDP port scanner
Usage: python port_scanner.py <target> [options]
"""

import socket
import argparse
import sys
import threading
import queue
import time
from datetime import datetime

# Common ports and their services
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB", 5900: "VNC",
    20: "FTP-Data", 69: "TFTP", 161: "SNMP", 389: "LDAP",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 2049: "NFS", 2181: "Zookeeper", 5672: "RabbitMQ",
    6443: "Kubernetes", 9200: "Elasticsearch", 9300: "Elasticsearch-Transport"
}

open_ports = []
lock = threading.Lock()


def resolve_host(target: str) -> str:
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"[ERROR] Cannot resolve host: {target}")
        sys.exit(1)


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab a service banner."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        # Send a generic HTTP request for web ports
        if port in (80, 8080, 8000):
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        return banner[:100] if banner else ""
    except Exception:
        return ""


def scan_port(ip: str, port: int, timeout: float, grab_banners: bool):
    """Scan a single TCP port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()

        if result == 0:
            service = COMMON_SERVICES.get(port, "Unknown")
            banner = ""
            if grab_banners:
                banner = grab_banner(ip, port)

            with lock:
                open_ports.append(port)
                banner_str = f" | Banner: {banner}" if banner else ""
                print(f"  [OPEN]  Port {port:>5} | {service:<20}{banner_str}")
    except Exception:
        pass


def worker(ip: str, port_queue: queue.Queue, timeout: float, grab_banners: bool):
    """Thread worker function."""
    while True:
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            break
        scan_port(ip, port, timeout, grab_banners)
        port_queue.task_done()


def parse_ports(port_str: str) -> list:
    """Parse port string like '80,443,1000-2000' into a list of ports."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def print_banner(target: str, ip: str, ports: list, threads: int, timeout: float):
    """Print scan header."""
    print("=" * 60)
    print("           PYTHON PORT SCANNER")
    print("=" * 60)
    print(f"  Target   : {target}")
    if target != ip:
        print(f"  IP       : {ip}")
    print(f"  Ports    : {len(ports)} port(s)")
    print(f"  Threads  : {threads}")
    print(f"  Timeout  : {timeout}s")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print()


def print_summary(start_time: float):
    """Print scan summary."""
    elapsed = time.time() - start_time
    print()
    print("=" * 60)
    print("  SCAN COMPLETE")
    print("=" * 60)
    if open_ports:
        print(f"  Open Ports : {', '.join(map(str, sorted(open_ports)))}")
    else:
        print("  No open ports found.")
    print(f"  Total Open : {len(open_ports)}")
    print(f"  Time Taken : {elapsed:.2f} seconds")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Simple Python Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py 192.168.1.1
  python port_scanner.py example.com -p 80,443,8080
  python port_scanner.py 10.0.0.1 -p 1-1024 -t 100
  python port_scanner.py localhost -p 1-65535 --timeout 0.5 --banners
        """
    )
    parser.add_argument("target", help="Target host (IP or hostname)")
    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        help="Ports to scan (e.g. 80,443 or 1-1024). Default: 1-1024"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int, default=50,
        help="Number of threads. Default: 50"
    )
    parser.add_argument(
        "--timeout",
        type=float, default=1.0,
        help="Connection timeout in seconds. Default: 1.0"
    )
    parser.add_argument(
        "--banners",
        action="store_true",
        help="Attempt to grab service banners"
    )
    parser.add_argument(
        "--common",
        action="store_true",
        help="Scan only common/well-known ports"
    )

    args = parser.parse_args()

    # Resolve target
    ip = resolve_host(args.target)

    # Determine ports
    if args.common:
        ports = sorted(COMMON_SERVICES.keys())
    else:
        try:
            ports = parse_ports(args.ports)
        except ValueError:
            print("[ERROR] Invalid port format. Use: 80,443 or 1-1024")
            sys.exit(1)

    # Validate port range
    ports = [p for p in ports if 1 <= p <= 65535]
    if not ports:
        print("[ERROR] No valid ports to scan.")
        sys.exit(1)

    print_banner(args.target, ip, ports, args.threads, args.timeout)

    # Build queue
    port_queue = queue.Queue()
    for port in ports:
        port_queue.put(port)

    start_time = time.time()

    # Launch threads
    threads = []
    num_threads = min(args.threads, len(ports))
    for _ in range(num_threads):
        t = threading.Thread(
            target=worker,
            args=(ip, port_queue, args.timeout, args.banners),
            daemon=True
        )
        t.start()
        threads.append(t)

    # Wait for completion
    for t in threads:
        t.join()

    print_summary(start_time)


if __name__ == "__main__":
    main()
