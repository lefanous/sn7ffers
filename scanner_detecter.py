#/usr/bin/env python3

from scapy.all import *  # Import the Scapy library for working with network packets
from functools import partial
import threading
import time
import os
import netifaces as ni
from src.utils.ascii import ascii_art
from src.utils.scanner_patterns import scanner_patterns, pattern_match
from src.utils.interface import get_interfaces, get_internal_ip, choose_interface
from src.utils.print import periodic_scan_detection

# Initialize dictionaries to store captured data
connections = {}

def monitor_packet(internal_ip, pkt):
    if IP in pkt and TCP in pkt:  # Check if the packet is an IP and TCP packet
        src_ip = pkt[IP].src  # Get the source IP address from the packet
        dst_ip = pkt[IP].dst  # Get the destination IP address from the packet
        dst_port = pkt[TCP].dport  # Get the destination port from the packet
        src_port = pkt[TCP].sport  # Get the source port from the packet
        tcp_flag = pkt[TCP].flags  # Get the TCP flags from the packet
        window_size = pkt[TCP].window  # Get the TCP window size from the packet

        # Define the key for the captured data dictionary
        attacker_ip = src_ip if src_ip != internal_ip else dst_ip
        target_port = dst_port if src_ip != internal_ip else src_port

        connection_key = (attacker_ip, target_port)

        # Initialize or update the connection data
        if connection_key not in connections:
            connections[connection_key] = {"tcp_flags": [(tcp_flag, window_size)],
                                           "status": "Closed",
                                           "src_port": src_port,
                                           "dst_ports": [dst_port],
                                           "timestamp": time.time()}
        else:
            connections[connection_key]["tcp_flags"].append((tcp_flag, window_size))
            if dst_port not in connections[connection_key]["dst_ports"]:
                connections[connection_key]["dst_ports"].append(dst_port)


if __name__ == '__main__':
    interfaces = get_interfaces()
    selected_interface = choose_interface(interfaces)
    print(f"Sniffing on interface: {selected_interface}")

    internal_ip = get_internal_ip()

    # Start the periodic scan detection in a separate thread
    periodic_scan_detection_partial = partial(periodic_scan_detection, internal_ip, selected_interface, connections, scanner_patterns, pattern_match)
    detection_thread = threading.Thread(target=periodic_scan_detection_partial)
    detection_thread.daemon = True  # This makes the thread exit when the main program exits
    detection_thread.start()

    # Start sniffing
    monitor_packet_internal_ip = partial(monitor_packet, internal_ip)
    sniff(prn=monitor_packet_internal_ip, store=0, iface=selected_interface)  # Start capturing packets on the chosen interface
