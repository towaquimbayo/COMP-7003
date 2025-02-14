# Parse Ethernet header
def parse_ethernet_header(hex_data):
    """
    Parses the Ethernet header from a hex string of data and prints the results
    and routes the payload to the corresponding parser based on the EtherType field (ARP or IPv4).
    :param hex_data: The hex string of data to parse representing the Ethernet segment.
    :return: A tuple containing the EtherType and the payload data.
    """
    dest_mac = ":".join(hex_data[i: i + 2] for i in range(0, 12, 2))
    source_mac = ":".join(hex_data[i: i + 2] for i in range(12, 24, 2))
    ether_type = hex_data[24:28]
    payload = hex_data[28:]

    print(f"Ethernet Header:")
    print(f"  {'Destination MAC:':<25} {hex_data[0:12]:<20} | {dest_mac}")
    print(f"  {'Source MAC:':<25} {hex_data[12:24]:<20} | {source_mac}")
    print(f"  {'EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")

    # Route payload based on EtherType (ARP or IPv4)
    if ether_type == "0806":  # ARP
        parse_arp_header(payload)
    elif ether_type == "0800":  # IPv4
        parse_ipv4_header(payload)
    else:
        print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload


# Parse ARP header
def parse_arp_header(hex_data):
    """
    Parses the ARP header from a hex string of data and prints the results.
    :param hex_data: The hex string of data to parse representing the ARP segment.
    :return: None
    """
    try:
        hardware_type = int(hex_data[:4], 16)
        protocol_type = int(hex_data[4:8], 16)
        hardware_size = int(hex_data[8:10], 16)
        protocol_size = int(hex_data[10:12], 16)
        operation = int(hex_data[12:16], 16)
        sender_mac = ":".join(hex_data[i: i + 2] for i in range(16, 28, 2))
        sender_ip = ".".join(str(int(hex_data[i: i + 2], 16)) for i in range(28, 36, 2))
        target_mac = ":".join(hex_data[i: i + 2] for i in range(36, 48, 2))
        target_ip = ".".join(str(int(hex_data[i: i + 2], 16)) for i in range(48, 56, 2))

        print(f"ARP Header:")
        print(f"  {'Hardware Type:':<25} {hex_data[:4]:<20} | {hardware_type}")
        print(f"  {'Protocol Type:':<25} {hex_data[4:8]:<20} | {protocol_type}")
        print(f"  {'Hardware Size:':<25} {hex_data[8:10]:<20} | {hardware_size}")
        print(f"  {'Protocol Size:':<25} {hex_data[10:12]:<20} | {protocol_size}")
        print(f"  {'Operation:':<25} {hex_data[12:16]:<20} | {operation}")
        print(f"  {'Sender MAC:':<25} {hex_data[16:28]:<20} | {sender_mac}")
        print(f"  {'Sender IP:':<25} {hex_data[28:36]:<20} | {sender_ip}")
        print(f"  {'Target MAC:':<25} {hex_data[36:48]:<20} | {target_mac}")
        print(f"  {'Target IP:':<25} {hex_data[48:56]:<20} | {target_ip}")
    except Exception as e:
        print(f"Error parsing ARP header: {e}")


# Parse IPv4 header
def parse_ipv4_header(hex_data):
    """
    Parses the IPv4 header from a hex string of data and prints the results
    and routes the payload based on the Protocol field (UDP, TCP, ICMP).
    :param hex_data: The hex string of data to parse representing the IPv4 segment.
    :return: None
    """
    try:
        version = int(hex_data[0], 16)
        header_length = int(hex_data[1], 16) * 4
        total_length = int(hex_data[4:8], 16)
        flags_and_frag = hex_data[12:16]
        flags_and_frag_int = int(flags_and_frag, 16)
        flags_and_frag_bin = bin(flags_and_frag_int)
        fragment_offset = flags_and_frag_int & 0x1FFF
        protocol = int(hex_data[18:20], 16)
        source_ip = ".".join(str(int(hex_data[i: i + 2], 16)) for i in range(24, 32, 2))
        dest_ip = ".".join(str(int(hex_data[i: i + 2], 16)) for i in range(32, 40, 2))

        print("IPv4 Header:")
        print(f"  {'Version:':<25} {hex_data[0]:<20} | {version}")
        print(f"  {'Header Length:':<25} {hex_data[1]:<20} | {header_length} bytes")
        print(f"  {'Total Length:':<25} {hex_data[4:8]:<20} | {total_length}")
        print(f"  {'Flags & Frag Offset:':<25} {flags_and_frag:<20} | {flags_and_frag_bin}")
        print(f"    {'Reserved:':<25} {(flags_and_frag_int >> 15) & 1:<20}")
        print(f"    {'DF (Do Not Fragment):':<25} {(flags_and_frag_int >> 14) & 1:<20}")
        print(f"    {'MF (More Fragments):':<25} {(flags_and_frag_int >> 13) & 1:<20}")
        print(f"    {'Fragment Offset:':<25} 0x{fragment_offset:X} | {fragment_offset}")
        print(f"  {'Protocol:':<25} {hex_data[18:20]:<20} | {protocol}")
        print(f"  {'Source IP:':<25} {hex_data[24:32]:<20} | {source_ip}")
        print(f"  {'Destination IP:':<25} {hex_data[32:40]:<20} | {dest_ip}")

        # Route payload based on protocol (UDP, TCP, ICMP)
        payload = hex_data[header_length * 2:]
        if protocol == 1:  # ICMP
            parse_icmp_header(payload)
        elif protocol == 6:  # TCP
            parse_tcp_header(payload)
        elif protocol == 17:  # UDP
            parse_udp_header(payload)
        else:
            print(f"  {'Unknown Protocol:':<25} {protocol:<20} | {protocol}")
            print("  No parser available for this Protocol.")
    except Exception as e:
        print(f"Error parsing IPv4 header: {e}")


# Parse ICMP header
def parse_icmp_header(hex_data):
    """
    Parses the ICMP header from a hex string of data and prints the results.
    :param hex_data: The hex string of data to parse representing the ICMP segment.
    :return: None
    """
    icmp_type = int(hex_data[:2], 16)
    icmp_code = int(hex_data[2:4], 16)
    icmp_checksum = int(hex_data[4:8], 16)
    payload_hex = hex_data[8:]

    print(f"ICMP Header:")
    print(f"  {'Type:':<25} {hex_data[:2]:<20} | {icmp_type}")
    print(f"  {'Code:':<25} {hex_data[2:4]:<20} | {icmp_code}")
    print(f"  {'Checksum:':<25} {hex_data[4:8]:<20} | {icmp_checksum}")
    print(f"  {'Payload (hex):':<25} {payload_hex}")


# Parse TCP header
def parse_tcp_header(hex_data):
    """
    Parses the TCP header from a hex string of data and prints the results.
    :param hex_data: The hex string of data to parse representing the TCP segment.
    :return: None
    """
    source_port = int(hex_data[:4], 16)
    dest_port = int(hex_data[4:8], 16)
    seq_num = int(hex_data[8:16], 16)
    ack_num = int(hex_data[16:24], 16)
    data_offset = (int(hex_data[24:26], 16) >> 4) * 4
    reserved = (int(hex_data[24:26], 16) >> 1) & 7
    flags = int(hex_data[26:28], 16)
    window_size = int(hex_data[28:32], 16)
    checksum = int(hex_data[32:36], 16)
    urgent_pointer = int(hex_data[36:40], 16)
    payload_hex = hex_data[data_offset * 2:]

    print(f"TCP Header:")
    print(f"  {'Source Port:':<25} {hex_data[:4]:<20} | {source_port}")
    print(f"  {'Destination Port:':<25} {hex_data[4:8]:<20} | {dest_port}")
    print(f"  {'Sequence Number:':<25} {hex_data[8:16]:<20} | {seq_num}")
    print(f"  {'Acknowledgment Number:':<25} {hex_data[16:24]:<20} | {ack_num}")
    print(f"  {'Data Offset:':<25} {hex_data[24:26]:<20} | {data_offset} bytes")
    print(f"  {'Reserved:':<25} 0b{bin(reserved)[2:]:<18} | {reserved}")
    print(f"  {'Flags:':<25} 0b{bin(flags)[2:].zfill(8):<18} | {flags}")
    print(f"    {'NS:':<25} {(flags >> 8) & 1:<20}")
    print(f"    {'CWR:':<25} {(flags >> 7) & 1:<20}")
    print(f"    {'ECE:':<25} {(flags >> 6) & 1:<20}")
    print(f"    {'URG:':<25} {(flags >> 5) & 1:<20}")
    print(f"    {'ACK:':<25} {(flags >> 4) & 1:<20}")
    print(f"    {'PSH:':<25} {(flags >> 3) & 1:<20}")
    print(f"    {'RST:':<25} {(flags >> 2) & 1:<20}")
    print(f"    {'SYN:':<25} {(flags >> 1) & 1:<20}")
    print(f"    {'FIN:':<25} {flags & 1:<20}")
    print(f"  {'Window Size:':<25} {hex_data[28:32]:<20} | {window_size}")
    print(f"  {'Checksum:':<25} {hex_data[32:36]:<20} | {checksum}")
    print(f"  {'Urgent Pointer:':<25} {hex_data[36:40]:<20} | {urgent_pointer}")
    print(f"  {'Payload (hex):':<25} {payload_hex:<20}")


# Parse UDP header
def parse_udp_header(hex_data):
    """
    Parses the UDP header from a hex string of data and prints the results.
    :param hex_data: The hex string of data to parse representing the UDP segment.
    :return: None
    """
    source_port = int(hex_data[:4], 16)
    dest_port = int(hex_data[4:8], 16)
    length = int(hex_data[8:12], 16)
    checksum = int(hex_data[12:16], 16)
    payload_hex = hex_data[16:]

    print(f"UDP Header:")
    print(f"  {'Source Port:':<25} {hex_data[:4]:<20} | {source_port}")
    print(f"  {'Destination Port:':<25} {hex_data[4:8]:<20} | {dest_port}")
    print(f"  {'Length:':<25} {hex_data[8:12]:<20} | {length}")
    print(f"  {'Checksum:':<25} {hex_data[12:16]:<20} | {checksum}")
    print(f"  {'Payload (hex):':<25} {payload_hex}")

    # Check if the UDP packet is carrying DNS traffic
    if source_port == 53 or dest_port == 53:
        print("Detected DNS traffic")
        parse_dns_header(payload_hex)


# Parse DNS header
def parse_dns_header(hex_data):
    """
    Parses the DNS header from a hex string of data and prints the results.
    :param hex_data: The hex string of data to parse representing the DNS segment.
    :return: None
    """
    transaction_id = hex_data[:4]
    flags = int(hex_data[4:8], 16)
    qd_count = int(hex_data[8:12], 16)
    an_count = int(hex_data[12:16], 16)
    ns_count = int(hex_data[16:20], 16)
    ar_count = int(hex_data[20:24], 16)

    print(f"DNS Header:")
    print(f"  {'Transaction ID:':<25} {transaction_id}")
    print(f"  {'Flags:':<25} 0b{bin(flags)[2:].zfill(16)} | {flags}")
    print(f"  {'Questions:':<25} {qd_count}")
    print(f"  {'Answers:':<25} {an_count}")
    print(f"  {'Authority RRs:':<25} {ns_count}")
    print(f"  {'Additional RRs:':<25} {ar_count}")
    print(f"  {'Payload (hex):':<25} {hex_data[24:]}")