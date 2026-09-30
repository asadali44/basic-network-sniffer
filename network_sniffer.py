from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


def analyze_packet(packet):
    # Check whether the packet contains an IP layer
    if IP in packet:

        # Get source and destination IP addresses
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        # Identify the protocol
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = str(packet[IP].proto)

        # Display basic packet information
        print("\n" + "=" * 60)
        print(f"Source IP       : {source_ip}")
        print(f"Destination IP  : {destination_ip}")
        print(f"Protocol        : {protocol}")

        # Display TCP information
        if TCP in packet:
            print(f"Source Port     : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        # Display UDP information
        elif UDP in packet:
            print(f"Source Port     : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        # Display ICMP information
        elif ICMP in packet:
            print(f"ICMP Type       : {packet[ICMP].type}")
            print(f"ICMP Code       : {packet[ICMP].code}")

        # Display payload information
        if Raw in packet:
            payload = packet[Raw].load

            print(f"Payload Size    : {len(payload)} bytes")

            # Show only first 50 bytes as hexadecimal
            preview = payload[:50].hex()
            print(f"Payload Preview : {preview}")

        else:
            print("Payload         : None")

        # Display total packet length
        print(f"Packet Length   : {len(packet)} bytes")


# Program starting message
print("=" * 60)
print("           BASIC NETWORK SNIFFER")
print("=" * 60)
print("Starting Network Sniffer...")
print("Press CTRL+C to stop.")
print("=" * 60)


# Start capturing packets
try:
    sniff(
        prn=analyze_packet,
        store=False
    )

except KeyboardInterrupt:
    print("\n\nNetwork Sniffer stopped.")
    print("Thank you!")