import argparse
import socket
import subprocess
import re
from scapy.all import *
from netaddr import IPNetwork, IPRange  # Ensure netaddr is installed


# Function to detect local subnet (if no target is provided)
def get_local_subnet():
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)

        for line in result.stdout.split("\n"):
            if "src" in line:
                match = re.search(r"src (\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    local_ip = match.group(1)
                    subnet = local_ip.rsplit(".", 1)[0] + ".0/24"
                    print(f"[*] No target specified. Scanning local subnet: {subnet}")
                    return subnet

        print("[!] Could not detect local network, using fallback method.")
        fallback_ip = socket.gethostbyname(socket.gethostname())
        subnet = fallback_ip.rsplit(".", 1)[0] + ".0/24"
        return subnet

    except Exception as e:
        print(f"[!] Failed to detect local subnet: {e}")
        return "192.168.0.0/24"  # Default if detection fails


# Function to check if a host is online using ARP
def is_host_online(target):
    """
    Uses ARP to check if a target is online.
    Loopback addresses (127.x.x.x) are always considered reachable.
    """
    if target.startswith("127."):
        return True

    ans, _ = arping(target, timeout=1, verbose=False)
    return len(ans) > 0


# Function to perform a SYN scan on a given port
def syn_scan(target, port):
    """
    Constructs a SYN packet using Scapy and sends the SYN packet to the target.
    Then to analyze the response:
    - if SYN-ACK received, port is OPEN
    - if RST received, port is CLOSED
    - if no response, port is FILTERED
    Return the appropriate status as a string: "open", "closed", or "filtered"
    """

    # Create the SYN packet
    ip_packet = IP(dst=target)
    tcp_packet = TCP(dport=port, flags="S")
    syn_packet = ip_packet / tcp_packet

    # Send the SYN packet to the target
    response = sr1(syn_packet, timeout=1, verbose=False)

    # Check response
    if response is None:
        return "filtered"
    elif response.haslayer(TCP):
        flags = response.getlayer(TCP).flags
        if flags == 0x12:  # SYN-ACK
            ip_packet = IP(dst=target)
            tcp_packet = TCP(dport=port, flags="R")
            rst_packet = ip_packet / tcp_packet  # reset packet
            send(rst_packet, verbose=False)
            return "open"
        elif flags == 0x14:  # RST
            return "closed"
    return "filtered"


# Function to scan a given target on specified ports
def scan_target(target, ports, open_hosts, closed_hosts, filtered_hosts):
    """
    Prints the scanning message with the target IP and port range.
    Uses is_host_online(target) to check if the host is reachable.
    If the host is online, iterate through the ports and:
    - Call `syn_scan(target, port)` for each port.
    - Categorize the result into open, closed, or filtered lists.
    """
    print(f"[+] Scanning {target} on ports {min(ports)}-{max(ports)}...")

    if not is_host_online(target):
        print(f"[-] {target} is unreachable. Skipping...")
        return

    for port in ports:
        print(f"[+] Scanning {target}:{port}...")
        result = syn_scan(target, port)

        if result == "open":
            open_hosts.append((target, port))
        elif result == "closed":
            closed_hosts.append((target, port))
        elif result == "filtered":
            filtered_hosts.append((target, port))


# Function to parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="SYN Scanner Shell for Students")
    parser.add_argument("-t", "--target", help="Target IP, range, or subnet")
    parser.add_argument("-p", "--ports", help="Port(s) to scan (e.g., 80,443,1-100)")
    parser.add_argument("--show", help="Filter results: open, closed, filtered")

    args = parser.parse_args()

    if not args.target:
        args.target = get_local_subnet()

    targets = []
    for target_ips in args.target.split(","):
        if "-" in target_ips:  # range of IPs
            start_ip, end_ip = target_ips.split("-")
            targets.extend(str(ip) for ip in IPRange(start_ip, end_ip))
        elif "/" in target_ips:  # subnet of IPs
            targets.extend(str(ip) for ip in IPNetwork(target_ips))
        else:  # single IP
            targets.append(target_ips)

    ports = []
    if args.ports:
        for port_nums in args.ports.split(","):
            if "-" in port_nums:  # range of ports
                start_port, end_port = map(int, port_nums.split("-"))
                ports.extend(range(start_port, end_port + 1))
            else:  # single port
                ports.append(int(port_nums))
    else:
        ports = list(range(1, 65536))  # all 65535 ports.

    return targets, ports, args.show


if __name__ == "__main__":
    """
    - Call `parse_arguments()` to get the list of targets and ports.
    - Create empty lists for open, closed, and filtered ports.
    - Loop through each target and call `scan_target()`.
    - Print a final summary of open, closed, and filtered ports.
    """
    targets, ports, filter_res = parse_arguments()

    open_hosts = []
    closed_hosts = []
    filtered_hosts = []

    print("\n[+] Starting scan of target(s)...")
    for target in targets:
        scan_target(target, ports, open_hosts, closed_hosts, filtered_hosts)

    print("\n[+] Final Scan Summary:")
    if not filter_res or "open" in filter_res:
        if len(open_hosts) > 0:
            print(f"  Open Ports:")
            for host in open_hosts:
                print(f"    - {host[0]}:{host[1]}")
        else:
            print(f"  Open Ports: {open_hosts}")
    if not filter_res or "closed" in filter_res:
        if len(closed_hosts) > 0:
            print(f"  Closed Ports:")
            for host in closed_hosts:
                print(f"    - {host[0]}:{host[1]}")
        else:
            print(f"  Closed Ports: {closed_hosts}")
    if not filter_res or "filtered" in filter_res:
        if len(filtered_hosts) > 0:
            print(f"  Filtered Ports:")
            for host in filtered_hosts:
                print(f"    - {host[0]}:{host[1]}")
        else:
            print(f"  Filtered Ports: {filtered_hosts}")
