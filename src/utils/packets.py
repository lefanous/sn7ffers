def extract_packet_info(packet):
    if IP in packet and TCP in packet: # Check if the packet is an IP and TCP packet
        return {
            "src_ip": packet[IP].src, # Get the source IP address from the packet
            "dst_ip": packet[IP].dst, # Get the destination IP address from the packet
            "dst_port": packet[TCP].dport, # Get the destination port from the packet
            "src_port": packet[TCP].sport, # Get the source port from the packet
            "tcp_flag": packet[TCP].flags, # Get the TCP flags from the packet
            "window_size": packet[TCP].window, # Get the TCP window size from the packet
        }
    else:
        return None
