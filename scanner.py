import socket
import sys
import concurrent.futures

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
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                open_ports.append({"port": port, "banner": banner})
                banner_display = f" [Banner: {banner}]" if banner else ""
                print(f"[+] Port {port}/TCP is OPEN{banner_display}")
                
    if not open_ports:
        print("[-] No open ports found on this host.")
    return open_ports

if __name__ == "__main__":
    test_ports = parse_ports("80,443,8080-8085")
    scan_target("127.0.0.1", test_ports, 10)    
