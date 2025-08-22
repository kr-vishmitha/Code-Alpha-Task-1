from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    # Only handle packets with an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print("\n--- Relevant Packet Captured ---")
        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol       : {ip_layer.proto}")

        # Check for TCP layer
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print("Protocol Type  : TCP")
            print(f"Source Port    : {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")

        # Check for UDP layer
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print("Protocol Type  : UDP")
            print(f"Source Port    : {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")

        # Print raw payload if available
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                decoded = payload.decode('utf-8', errors='replace')
                print("Payload        :", decoded)
            except:
                print("Payload        : (Non-decodable content)")

# Start sniffing packets
print("🔍 Starting packet capture... (press Ctrl+C to stop)")
sniff(prn=packet_callback, store=False, count=50)