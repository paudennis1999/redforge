#!/usr/bin/env python3
"""RedForge Port Scanner - multi-threaded TCP scanner with banner grabbing,
SYN stealth mode and JSON report."""

import argparse
import ipaddress
import json
import os
import random
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from scapy.all import IP, TCP, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER = f"""{CYAN}{BOLD}
  ____          _ _____
 |  _ \\ ___  __| |  ___|__  _ __ __ _  ___
 | |_) / _ \\/ _` | |_ / _ \\| '__/ _` |/ _ \\
 |  _ <  __/ (_| |  _| (_) | | | (_| |  __/
 |_| \\_\\___|\\__,_|_|  \\___/|_|  \\__, |\\___|
                                 |___/
        Port Scanner  -  v2.2{RESET}
"""

# Ports where the server stays silent until the client speaks first.
# For these we send a minimal protocol probe before reading, instead of
# just listening — otherwise the banner grab always times out.
HTTP_LIKE_PORTS = {80, 8000, 8008, 8080, 8081, 8888, 9000, 9090}

COMMON_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 179, 389, 443, 445, 464, 465, 500, 514, 515, 587, 631,
    636, 993, 995, 1025, 1080, 1194, 1433, 1434, 1521, 1723, 2049, 2082,
    2083, 2222, 2375, 3128, 3268, 3269, 3306, 3389, 3690, 4444, 5000, 5432,
    5900, 5985, 5986, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090,
    9200, 9300, 10000, 27017,
]

ALL_PORTS = list(range(1, 65536))

# Ports used only for the fast host-discovery pre-pass (--discover). Picked to
# cover both worlds without relying on ICMP (blocked by the Windows Firewall
# by default, and often by network firewalls too): 445/139/135/3389 for
# Windows, 22 for Linux, 80/443 for anything web-facing, 53 for DNS servers.
# A host is "alive" if ANY of these gives a definitive answer - open OR
# actively refused (RST) - since a closed-but-reachable port already proves
# something is there to answer; only a timeout on all of them means "no
# reply from this address at all".
DISCOVERY_PORTS = [445, 139, 135, 3389, 22, 80, 443, 53]

# Global scan settings set from CLI args, read by scan_port() (same pattern
# already used for the "ip" variable in earlier versions of this script)
STEALTH = False


def check_port(ip, port, timeout=1):
    """TCP Connect Scan: check the state of a port via a full handshake."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return "open"
    except ConnectionRefusedError:
        return "closed"
    except socket.timeout:
        return "filtered"
    except OSError:
        # Catches other platform-specific socket errors (e.g. on Windows,
        # PermissionError/WinError 10013 when the OS or local
        # firewall/antivirus blocks the connection attempt at socket level,
        # often on ports reserved by other system services). Since the
        # connection could not be completed, "filtered" is the closest
        # honest classification.
        return "filtered"
    finally:
        s.close()


def syn_scan(ip, port, timeout=1, retries=1):
    """SYN (half-open) scan: send a SYN, read the flags of the reply, never
    complete the handshake. Requires root and the scapy library.

    Retries on "no response" only: under heavy thread concurrency, scapy's
    shared raw socket can lose/misattribute a reply, making a closed port
    look "filtered" by mistake. A definitive answer (open/closed) is never
    retried, only a missing one."""
    for attempt in range(retries + 1):
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=timeout, verbose=0)
        if response is None:
            continue
        elif response[TCP].flags == "SA":
            return "open"
        else:
            return "closed"
    return "filtered"


def grab_banner(ip, port, timeout=1):
    """Try to read the service banner from an open port (always via a normal
    TCP connection, even after a SYN scan discovery - a SYN scan alone never
    reads application data).

    Many protocols (FTP, SSH, SMTP, POP3, IMAP, Telnet...) are
    "server-initiated": they send a greeting the instant the TCP handshake
    completes, so a plain connect()+recv() is enough. Others (HTTP, SMB,
    LDAP, RPC, RDP, Kerberos...) are "client-initiated": the server stays
    silent until the client sends something in its expected format, so a
    blind recv() always just times out with nothing. For those we now send
    a small nudge first - a real HTTP request on well-known web ports, or a
    generic newline elsewhere, which is enough to make many text-based
    services respond even without knowing their exact protocol."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))

        if port in HTTP_LIKE_PORTS:
            try:
                s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            except OSError:
                pass
            data = s.recv(1024)
            if data:
                return data.decode(errors="ignore").strip()

        # Passive first: give server-initiated protocols a chance to speak
        # on their own before we nudge anything.
        s.settimeout(0.5)
        try:
            data = s.recv(1024)
            if data:
                return data.decode(errors="ignore").strip()
        except socket.timeout:
            pass

        # Still silent - try a generic nudge for text-based protocols that
        # only reply once they see a line ending.
        try:
            s.sendall(b"\r\n")
            s.settimeout(timeout)
            data = s.recv(1024)
            if data:
                return data.decode(errors="ignore").strip()
        except OSError:
            pass

        return "no banner"
    except socket.timeout:
        return "no banner"
    except OSError:
        return "no banner"
    finally:
        s.close()


def scan_port(ip, port, mode="connect", show_filtered=False):
    """Scan a single port on a single host; returns a dict for open/filtered, None for closed."""
    if STEALTH:
        time.sleep(random.uniform(0.1, 0.5))

    result = syn_scan(ip, port) if mode == "syn" else check_port(ip, port)

    if result == "closed":
        return None

    entry = {"ip": ip, "port": port, "status": result, "banner": ""}
    if result == "open":
        entry["banner"] = grab_banner(ip, port)
        print(f"{GREEN}[+] {ip}:{port} open{RESET}  {entry['banner']}")
    elif show_filtered:
        # Filtered ports are noisy on a full 65535-port scan and rarely
        # actionable live - hidden by default, still counted in the summary
        # and always kept in the JSON report. Pass --show-filtered to see
        # them as they're found.
        print(f"{YELLOW}[?] {ip}:{port} filtered{RESET}")
    return entry


def discover_host(ip, ports=DISCOVERY_PORTS, timeout=0.3):
    """Fast liveness check for one host: try a handful of ports with a short
    timeout and stop at the first definitive answer (open or closed/RST).
    Both mean the host is there; only "filtered" (timeout) on every port in
    the list means nothing answered. No ICMP involved - see DISCOVERY_PORTS
    for why."""
    for port in ports:
        if check_port(ip, port, timeout=timeout) in ("open", "closed"):
            return True
    return False


def discover_hosts(targets, workers=100):
    """Run discover_host() across every candidate IP in parallel, return only
    the ones that answered. This is the pre-pass --discover runs before the
    real (slower, full-port) scan, so a /24 doesn't spend its full per-port
    timeout budget on hosts that don't even exist."""
    alive = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(discover_host, ip): ip for ip in targets}
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                alive.append(ip)
                print(f"{GREEN}[+] {ip} is alive{RESET}")
    return alive


def parse_targets(target):
    """Accepts a single IP, CIDR (192.168.1.0/24) or a dash range (192.168.1.1-192.168.1.50)."""
    if "/" in target:
        network = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in network.hosts()]
    elif "-" in target:
        start_str, end_str = target.split("-")
        start = int(ipaddress.ip_address(start_str.strip()))
        end = int(ipaddress.ip_address(end_str.strip()))
        return [str(ipaddress.ip_address(i)) for i in range(start, end + 1)]
    else:
        return [target]


def print_summary(results, show_filtered=False):
    """Print a clean summary table of the findings, grouped by host.

    Open ports are always shown - that is the actionable signal. Filtered
    ports are noise on a full-range scan (thousands of identical lines
    telling you nothing but "no reply"), so by default only their count is
    shown; pass show_filtered=True (--show-filtered) to list them too. The
    JSON report always contains every entry regardless of this."""
    if not results:
        print(f"\n{YELLOW}No open or filtered ports found.{RESET}")
        return

    open_results = [e for e in results if e["status"] == "open"]
    filtered_count = len(results) - len(open_results)
    table_rows = results if show_filtered else open_results

    if table_rows:
        print(f"\n{BOLD}{'-'*60}{RESET}")
        print(f"{BOLD}{'IP':<16}{'PORT':<8}{'STATUS':<10}{'BANNER'}{RESET}")
        print(f"{BOLD}{'-'*60}{RESET}")

        for entry in sorted(table_rows, key=lambda e: (e["ip"], e["port"])):
            color = GREEN if entry["status"] == "open" else YELLOW
            print(f"{color}{entry['ip']:<16}{entry['port']:<8}{entry['status']:<10}{entry['banner']}{RESET}")

        print(f"{BOLD}{'-'*60}{RESET}")

    if not show_filtered and filtered_count:
        print(f"{YELLOW}[*] {filtered_count} filtered port(s) hidden - rerun with --show-filtered to list them{RESET}")


def interactive_menu():
    """Ask the user for target and port scope when no CLI argument was given."""
    print(f"{CYAN}{BOLD}=== Interactive menu ==={RESET}")
    target = input("Enter IP, CIDR (192.168.1.0/24) or range (192.168.1.1-192.168.1.50): ").strip()
    print("Ports to scan:")
    print("  1) Well-known ports (default)")
    print("  2) All ports (1-65535)")
    choice = input("Choice [1/2]: ").strip()
    ports_mode = "all" if choice == "2" else "common"
    return target, ports_mode


def main():
    global STEALTH

    parser = argparse.ArgumentParser(description="RedForge Port Scanner")
    parser.add_argument("target", nargs="?", default=None,
                         help="Single IP, CIDR or range (192.168.1.1-192.168.1.50). If omitted, opens the interactive menu.")
    parser.add_argument("--ports", choices=["common", "all"], default="common",
                         help="Well-known ports (default) or all 65535")
    parser.add_argument("--mode", choices=["connect", "syn"], default="connect",
                         help="connect = TCP Connect Scan (default, no privileges required); "
                              "syn = SYN/half-open scan (requires sudo and scapy)")
    parser.add_argument("--stealth", action="store_true",
                         help="Randomized port order + random delay between connections")
    parser.add_argument("--workers", type=int, default=None,
                         help="Parallel threads (default: 100 in connect mode, 10 in syn mode)")
    parser.add_argument("--discover", action="store_true",
                         help="Fast host-discovery pre-pass on a handful of common ports "
                              "(no ICMP - unreliable behind the Windows Firewall) before the "
                              "real scan; skips hosts that don't answer at all. Most useful "
                              "on a wide CIDR where most addresses are unassigned.")
    parser.add_argument("--output", default="scan_results.json", help="JSON output file")
    parser.add_argument("--show-filtered", action="store_true",
                         help="Print each filtered port as it's found, and list them in the summary table "
                              "(default: hidden, only counted - the JSON report always has them)")
    args = parser.parse_args()

    print(BANNER)

    if args.mode == "syn":
        if not SCAPY_AVAILABLE:
            print(f"{RED}[!] syn mode requires scapy: sudo apt install python3-scapy{RESET}")
            sys.exit(1)
        if os.name != "nt" and os.geteuid() != 0:
            print(f"{RED}[!] syn mode requires root privileges (raw socket): rerun with sudo{RESET}")
            sys.exit(1)

    STEALTH = args.stealth

    if args.workers is not None:
        workers = args.workers
    else:
        # syn mode needs a lower default: too many concurrent raw sockets
        # cause scapy to lose/misattribute replies (see syn_scan retries)
        workers = 10 if args.mode == "syn" else 100

    if args.target:
        target = args.target
        ports_mode = args.ports
    else:
        target, ports_mode = interactive_menu()

    targets = parse_targets(target)
    ports = list(COMMON_PORTS) if ports_mode == "common" else list(ALL_PORTS)

    if STEALTH:
        random.shuffle(ports)

    print(f"\n{CYAN}[*] Target : {len(targets)} host - {target}{RESET}")
    print(f"{CYAN}[*] Ports  : {ports_mode}{RESET}")
    print(f"{CYAN}[*] Mode   : {args.mode}{RESET}")
    print(f"{CYAN}[*] Stealth: {args.stealth}{RESET}")
    print(f"{CYAN}[*] Workers: {workers}{RESET}")
    print(f"{CYAN}[*] Discover: {args.discover}{RESET}\n")

    if args.discover and len(targets) > 1:
        print(f"{CYAN}[*] Host discovery pre-pass on {len(targets)} address(es)...{RESET}")
        targets = discover_hosts(targets, workers=workers)
        print(f"{CYAN}[*] {len(targets)} host(s) alive - scanning only those{RESET}\n")
        if not targets:
            print(f"{YELLOW}No host answered. Nothing to scan.{RESET}")
            sys.exit(0)

    jobs = [(ip, port) for ip in targets for port in ports]
    results = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(scan_port, ip, port, args.mode, args.show_filtered) for ip, port in jobs]
        for future in as_completed(futures):
            entry = future.result()
            if entry:
                results.append(entry)

    print_summary(results, args.show_filtered)

    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n{BOLD}[*] Done. {len(results)} ports found.{RESET}")
    print(f"{BOLD}[*] Report saved to {args.output}{RESET}")


if __name__ == "__main__":
    main()
