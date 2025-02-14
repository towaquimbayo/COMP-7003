import argparse
from scapy.all import AsyncSniffer, get_if_list, conf, rdpcap
from threading import Thread, Lock, Event
from packet_parsers import parse_ethernet_header
import socket
import psutil

# Suppress Scapy warnings
conf.logLevel = "ERROR"

# Shared counter, lock, and stop event for global packet handling
packet_counter = 0
counter_lock = Lock()
stop_event = Event()
global_packet_limit = 0


# Function to handle each captured packet
def packet_callback(packet):
    """
    Callback function to process each captured packet.
    :param packet: The captured packet to process.
    :return: None
    """
    global packet_counter
    with counter_lock:
        if packet_counter < global_packet_limit:
            packet_counter += 1
            print(f"\nCaptured Packet {packet_counter}:")
            raw_data = bytes(packet)
            hex_data = raw_data.hex()
            ether_type, payload = parse_ethernet_header(hex_data)

            # Stop capturing if the limit is reached
            if packet_counter >= global_packet_limit:
                stop_event.set()


# Function to check if an interface is a loopback interface
def interface_is_loopback(interface):
    """
    Checks if the specified interface is a loopback interface (i.e., 'lo', 'lo0')
    based on the IP address assigned to it.
    :param interface: The interface name to check.
    :return: True if the interface is a loopback interface, False otherwise.
    """
    try:
        addrs = psutil.net_if_addrs()
        if interface in addrs:
            for addr in addrs[interface]:
                if (
                    addr.family in (socket.AF_INET, socket.AF_INET6)
                    and addr.address == "127.0.0.1"
                ):
                    return True
                if addr.family == socket.AF_INET6 and addr.address == "::1":
                    return True
    except Exception as e:
        pass
    return False


def has_global_ip(interface):
    """
    Checks if the interface has an assigned global (non-link-local) IP address.
    :param interface: The interface name to check.
    :return: True if the interface has a global IP address, False otherwise.
    """
    try:
        addrs = psutil.net_if_addrs()
        if interface in addrs:
            for addr in addrs[interface]:
                # Check for IPv4 and IPv6 addresses
                if addr.family == socket.AF_INET and not addr.address.startswith(
                    "169.254"
                ):
                    return True
                if addr.family == socket.AF_INET6 and not addr.address.startswith(
                    "fe80"
                ):
                    return True
    except Exception as e:
        pass
    return False


# Capture packets on a specific interface
def capture_packets(interface, capture_filter):
    """
    Capture packets on a specific interface using the AsyncSniffer from Scapy
    and a packet callback function to process each packet.
    :param interface: The interface to capture packets on.
    :param capture_filter: The BPF filter to apply to the capture.
    :return: None
    """
    print(
        f"Starting packet capture on {interface} with filter: {capture_filter or 'None (all packets)'}"
    )
    try:
        # @Todo: Uncomment the following lines to read packets from a PCAP file
        # Read packets from a PCAP file for testing
        # packets = rdpcap("pcaps/all_interface_capture.pcap")
        # for packet in packets:
        #     packet_callback(packet)

        # Read packets using the AsyncSniffer to capture live packets
        sniffer = AsyncSniffer(
            iface=interface,
            filter=capture_filter if capture_filter else None,
            prn=packet_callback,
            store=False,
            stop_filter=lambda x: stop_event.is_set(),
        )
        sniffer.start()
        while not stop_event.is_set():
            pass
        if sniffer.running:  # Only stop if it's still running
            sniffer.stop()
    except KeyboardInterrupt:
        print(f"\nPacket capture stopped on {interface}.")
    except Exception as e:
        print(f"Error on interface {interface}: {e}")
    else:
        print(f"Packet capture completed on {interface}.")


# Capture packets on all interfaces
def capture_on_all_interfaces(capture_filter, packet_count):
    """
    Capture packets on all available interfaces with global IP addresses
    by starting a separate capture thread for each interface.
    :param capture_filter: The BPF filter to apply to each interface.
    :param packet_count: The number of packets to capture on each interface.
    :return: None
    """
    global global_packet_limit
    global_packet_limit = packet_count

    interfaces = get_if_list()
    print(f"Available interfaces: {interfaces}")
    threads = []

    for interface in interfaces:
        # Skip loopback and interfaces without global IPs
        if interface_is_loopback(interface):
            continue
        if not has_global_ip(interface):
            continue

        print(f"Starting packet capture on {interface}")
        thread = Thread(target=capture_packets, args=(interface, capture_filter))
        thread.start()
        threads.append(thread)

    # Wait for the stop_event to be set
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("\nPacket capture interrupted. Cleaning up...")
        stop_event.set()
        for thread in threads:
            thread.join()


# Main execution with argparse
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Packet sniffer using Scapy with manual HEX parsing"
    )
    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help="The interface to capture packets on (e.g., eth0, wlan0, any)",
    )
    parser.add_argument(
        "-f",
        "--filter",
        help="BPF filter to apply (e.g., 'tcp and port 80'). If not provided, captures all packets.",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        required=True,
        help="Number of packets to capture.",
    )
    args = parser.parse_args()

    if args.count < 1:
        print("Error: Packet count must be greater than 0.")
        exit(1)
    if args.interface.lower() == "any":
        capture_on_all_interfaces(args.filter, args.count)
    else:
        if has_global_ip(args.interface):
            try:
                capture_packets(args.interface, args.filter)
            except Exception as e:
                print(f"Error: Failed to capture on interface '{args.interface}'. {e}")
        else:
            print(
                f"Error: The specified interface '{args.interface}' does not have an assigned global IP address."
            )
