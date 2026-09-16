import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
}

def grab_banner(s: socket.socket, port: int) -> str:
    #Attempt to receive a banner payload from an open socket connection
    try:
        #HTTP/HTTPS usually require a request before sending a server header
        if port in (80,8080):
            s.sendall(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
        elif port == 443:
            #Plain sockets won't negotiate SSL/TLS, skip or wrap with SSL module
            return "TLS/SSL (Handshake required)"

        #Read up to 1024 bytes of the banner response
        banner_bytes = s.recv(1024)
        if banner_bytes:
            #Decode ASCII and clean up trailing newlines or whitespaces
            banner = banner_bytes.decode("utf-8", errors="ignore").strip()
            #Return only the first line of multi-line banners for cleaner output
            return banner.splitlines()[0]
    except (socket.timeout, socket.error):
        pass

    return "No banner returned"

def scan_port(target_ip: str, port: int, timeout: float = 1.5) -> tuple[int, bool, str, str]:
    #Scans a TCP port and attempts to grab the service banner if open
    service = COMMON_PORTS.get(port, "Unknown")
    try:
        #Create a TCP socket (IPv4, Streaming)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            # connect_ex returns 0 on success, or an error code on failure
            result = s.connect_ex((target_ip, port))
            if result == 0:
                banner = grab_banner(s, port)
                return (port, True, service, banner)
    except socket.error:
        pass
    return (port, False, service, "")


def run_scanner(
    target: str, ports: list[int] = None, max_threads: int = 20
) -> None:
    #Scans the specified target IP for open ports using thread concurrency.
    try:
        #Validate and normalize IP input
        target_ip = str(ipaddress.ip_address(target))
    except ValueError:
        try:
            #Resolve hostname if a domain was provided
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            print(f"[-] Error: Could not resolve target '{target}'.")
            return

    if ports is None:
        ports = sorted(list(COMMON_PORTS.keys()))

    print(f"\n[+] Starting scan on target: {target} ({target_ip})")
    print(f"[+] Scanning {len(ports)} ports using {max_threads} threads...\n")
    print(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<15}")
    print("-" * 35)

    open_ports_count = 0

    #Use ThreadPoolExecutor for faster non-blocking network I/O
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [
            executor.submit(scan_port, target_ip, port) for port in ports
        ]

        for future in futures:
            port, is_open, service, banner = future.result()
            if is_open:
                print(f"{port:<8}{'OPEN':<8}{service:<12}{banner}")
                open_ports_count += 1

    print("-" * 65)
    print(f"[+] Scan complete. Found {open_ports_count} open port(s).\n")


if __name__ == "__main__":
    #Test against localhost (127.0.0.1) or scanme.nmap.org
    target_host = input("Enter target IP or hostname (default: scanme.nmap.org): ").strip()
    if not target_host:
        target_host = "scanme.nmap.org"

    #Example: Scan common ports or pass custom range like list(range(1, 1025))
    run_scanner(target_host)