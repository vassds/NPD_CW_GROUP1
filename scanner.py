import socket
import argparse
import ipaddress
import concurrent.futures
import time
import json
import sys

def parse_ports(port_string):
    """
    Parses a port string (e.g., '80,443' or '20-100') into a list of integers.
    """
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

def grab_banner(sock):
    """
    Attempts to grab the service banner from an open port.
    """
    try:
        sock.settimeout(0.5) 
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        return banner.replace('\r', '').replace('\n', ' ')[:50] 
    except (socket.timeout, ConnectionResetError, OSError):
        return ""

def scan_port(ip, port):
    """
    Attempts a TCP connection to a specific IP and port.
    Returns a tuple: (port, is_open, banner)
    """
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
    """
    Scans a list of ports for a single IP address using ThreadPoolExecutor.
    Includes a dynamic progress bar.
    """
    open_ports = []
    total_ports = len(ports)
    completed_ports = 0
    
    print(f"\n[*] Scanning Target: {ip}")
    print("-" * 50)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        
        for future in concurrent.futures.as_completed(futures):
            port, is_open, banner = future.result()
            completed_ports += 1
            
            # --- Progress Bar Math ---
            percent = (completed_ports / total_ports) * 100
            bar_length = 30
            filled_length = int(bar_length * completed_ports // total_ports)
            bar = '█' * filled_length + '-' * (bar_length - filled_length)
            
            # If a port is open, carefully print it without breaking the progress bar
            if is_open:
                open_ports.append({"port": port, "banner": banner})
                banner_display = f" [Banner: {banner}]" if banner else ""
                
                # Clear the current progress bar line, print the open port, then let the loop redraw the bar
                sys.stdout.write('\r' + ' ' * 80 + '\r') 
                print(f"[+] Port {port}/TCP is OPEN{banner_display}")
                
            # Redraw the progress bar using carriage return (\r) to overwrite the same line
            sys.stdout.write(f'\r[*] Progress: |{bar}| {percent:.1f}% ({completed_ports}/{total_ports})')
            sys.stdout.flush()
            
    print() # Print a final newline when the progress bar reaches 100%
                
    if not open_ports:
        print("[-] No open ports found on this host.")
        
    return open_ports

def main():
    parser = argparse.ArgumentParser(description="High-Performance Multi-threaded Network Scanner")
    parser.add_argument("-t", "--target", help="Target IP or CIDR Subnet (e.g., 192.168.1.0/24)")
    # Changed default to None to trigger interactive prompt if omitted
    parser.add_argument("-p", "--ports", default=None, help="Port range to scan (format: 20-100 or 80,443)")
    parser.add_argument("-T", "--threads", type=int, default=None, help="Number of concurrent threads")
    parser.add_argument("-o", "--output", help="Output file to save results in JSON format")
    
    args = parser.parse_args()

    print(r"""
     _   _      _   ____                                
    | \ | | ___| |_/ ___|  ___ __ _ _ __  _ __   ___ _ __ 
    |  \| |/ _ \ __\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
    | |\  |  __/ |_ ___) | (_| (_| | | | | | | |  __/ |   
    |_| \_|\___|\__|____/ \___\__,_|_| |_|_| |_|\___|_|   
    """)
    
    # 1. Interactive Target Prompt
    if not args.target:
        try:
            args.target = input("[?] Enter Target IP or CIDR Subnet (e.g., 192.168.1.0/24): ").strip()
            if not args.target:
                print("[-] Error: Target cannot be empty. Exiting.")
                sys.exit(1)
        except KeyboardInterrupt:
            print("\n[-] Scan cancelled by user. Exiting gracefully...")
            sys.exit(0)

    # 2. Interactive Ports Prompt
    if args.ports is None:
        try:
            port_input = input("[?] Enter ports to scan (e.g., 80,443 or 20-100) [Default 1-1024]: ").strip()
            args.ports = port_input if port_input else "1-1024"
        except KeyboardInterrupt:
            print("\n[-] Scan cancelled by user. Exiting gracefully...")
            sys.exit(0)

    # 3. Interactive Threads Prompt
    if args.threads is None:
        try:
            thread_input = input("[?] Enter number of concurrent threads [Default 50]: ").strip()
            args.threads = int(thread_input) if thread_input else 50
        except ValueError:
            print("[-] Invalid number. Defaulting to 50 threads.")
            args.threads = 50
        except KeyboardInterrupt:
            print("\n[-] Scan cancelled by user. Exiting gracefully...")
            sys.exit(0)

    print("\n[*] Initializing Network Scanner...")
    
    # 4. Parse Inputs
    ports = parse_ports(args.ports)
    print(f"[*] Target(s): {args.target}")
    print(f"[*] Ports to scan: {len(ports)} (Threads: {args.threads})")
    
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

    # 5. Execute Scan
    try:
        for host in hosts:
            open_ports = scan_target(host, ports, args.threads)
            if open_ports:
                scan_results[str(host)] = open_ports
                
    except KeyboardInterrupt:
        print("\n\n[-] Scan interrupted by user. Exiting gracefully...")
        sys.exit(0)

    # 6. Finalize & Output Results
    end_time = time.time()
    print("\n" + "=" * 50)
    print(f"[*] Scan completed in {round(end_time - start_time, 2)} seconds.")
    print(f"[*] Total active hosts with open ports: {len(scan_results)}")
    print("=" * 50)

    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(scan_results, f, indent=4)
            print(f"[+] Results successfully saved to {args.output}")
        except IOError as e:
            print(f"[-] Failed to save output file: {e}")

if __name__ == "__main__":
    main()
