import socket
import sys
import concurrent.futures
import argparse
import ipaddress
import time
import json

def grab_banner(sock):
    try:
        sock.settimeout(0.5)
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        return banner.replace('\r', '').replace('\n', ' ')[:50]
    except (socket.timeout, ConnectionResetError, OSError):
        return ""


def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.0)
            result = sock.connect_ex((str(ip), port))
            if result == 0:
                banner = grab_banner(sock)
                return port, True, banner
            return port, False, None
    except Exception:
        return port, False, None


def scan_target(ip, ports, num_threads):
    open_ports = []
    print(f"\n[*] Scanning Target: {ip}")
    print("-" * 50)

    total_ports = len(ports)
    completed_ports = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open, banner = future.result()
            completed_ports += 1
            percent = (completed_ports / total_ports) * 100
            bar_length = 30
            filled_length = int(bar_length * completed_ports // total_ports)
            bar = '#' * filled_length + '-' * (bar_length - filled_length)

            if is_open:
                open_ports.append({"port": port, "banner": banner})
                banner_display = f" [Banner: {banner}]" if banner else ""
                sys.stdout.write('\r' + ' ' * 80 + '\r')
                print(f"[+] Port {port}/TCP is OPEN{banner_display}")

            sys.stdout.write(
                f'\r[*] Progress: |{bar}| {percent:.1f}% ({completed_ports}/{total_ports})'
            )
            sys.stdout.flush()

    print()
    if not open_ports:
        print("[-] No open ports found on this host.")
    return open_ports


def parse_ports(port_string):
    ports = set()
    try:
        parts = port_string.split(',')
        for part in parts:
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
        return sorted(list(ports))
    except ValueError:
        print("[-] Error: Invalid port format. Use '80,443' or '20-100'.")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="High-Performance Multi-threaded Network Scanner"
    )
    parser.add_argument("-t", "--target",  help="Target IP (e.g., 192.168.1.1)")
    parser.add_argument("-p", "--ports",   default=None, help="Port range to scan")
    parser.add_argument("-T", "--threads", type=int, default=None,
                        help="Number of concurrent threads")
   
    parser.add_argument("-o", "--output",
                        help="Output file to save results in JSON format")
   

    args = parser.parse_args()

    print(r"""
  _   _      _   ____
 | \ | | ___| |_/ ___| ___ __ _ _ __  _ __   ___ _ __
 |  \| |/ _ \ __\___ \/ __/ _` | '_ \| '_ \ / _ \ '__|
 | |\  |  __/ |_ ___) | (_| (_| | | | | | | |  __/ |
 |_| \_|\___|\__|____/ \___\__,_|_| |_|_| |_|\___|_|
    """)

    if not args.target:
        try:
            args.target = input("[?] Enter Target IP: ").strip()
            if not args.target:
                sys.exit(1)
        except KeyboardInterrupt:
            print("\n[!] Scan cancelled by user.")
            sys.exit(0)

    if args.ports is None:
        try:
            port_input = input(
                "[?] Enter ports to scan (e.g., 80,443 or 20-100) "
                "[Default 1-1024]: "
            ).strip()
            args.ports = port_input if port_input else "1-1024"
        except KeyboardInterrupt:
            print("\n[!] Scan cancelled by user.")
            sys.exit(0)

    if args.threads is None:
        try:
            thread_input = input(
                "[?] Enter number of concurrent threads [Default 50]: "
            ).strip()
            args.threads = int(thread_input) if thread_input else 50
        except (ValueError, KeyboardInterrupt):
            args.threads = 50

    print("\n[*] Initializing Network Scanner...")
    ports = parse_ports(args.ports)


    try:
        network = ipaddress.ip_network(args.target, strict=False)
        hosts = list(network.hosts())
        if not hosts:
            hosts = [ipaddress.ip_address(args.target)]
    except ValueError as e:
        print(f"[-] Invalid target network: {e}")
        sys.exit(1)

    scan_results = {}
    start_time = time.time()

    try:
        for host in hosts:
            open_ports = scan_target(host, ports, args.threads)
            if open_ports:
                scan_results[str(host)] = open_ports
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")

    end_time = time.time()
    print("\n" + "=" * 50)
    print(f"[*] Scan completed in {round(end_time - start_time, 2)} seconds.")
    print(f"[*] Total active hosts with open ports: {len(scan_results)}")
    print("=" * 50)

    if hasattr(args, 'output') and args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(scan_results, f, indent=4)
            print(f"[+] Results successfully saved to {args.output}")
        except IOError as e:
            print(f"[-] Failed to save output file: {e}")


if __name__ == "__main__":
    main()
