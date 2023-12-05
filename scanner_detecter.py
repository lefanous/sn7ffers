#/usr/bin/env python3

'''
----- README ----
## Objective:
Use Scapy to sniff the packets arriving at a network interface. After each packet is
captured, process it using a callback function to get useful information from it.

## Algorithm:
This script captures packets, tracks attempts a source IP makes to reach a specific destination IP and port,
and continuously displays this information on the screen. It checks for SYN-ACK or RST TCP flags to
determine if the port is open or closed.

## How to:
1. Import the file into your virtual machine,
2. Open your terminal, cd to the directory containing the source code
3. Run command: $chmod +x <file>, to make the file executable
4. Run the script with the following command: $sudo ./<file>
5. Use another/parallel terminal to run your scan as usual. The result should appear in the other terminal ;-)

## Note:
Feel free to add to this script. I haven't really made it robust, with error handling yet.
'''

from scapy.all import *  # Import the Scapy library for working with network packets
from functools import partial
import threading
import time
from helpers import ascii_art, scanner_patterns, pattern_match

# Initialize dictionaries to store captured data
connections = {}

def monitor_packet(internal_ip, pkt):
    if IP in pkt and TCP in pkt:  # Check if the packet is an IP and TCP packet
        src_ip = pkt[IP].src  # Get the source IP address from the packet
        dst_ip = pkt[IP].dst  # Get the destination IP address from the packet
        dst_port = pkt[TCP].dport  # Get the destination port from the packet
        src_port = pkt[TCP].sport  # Get the source port from the packet
        tcp_flag = pkt[TCP].flags  # Get the TCP flags from the packet

        # Define the key for the captured data dictionary
        attacker_ip = src_ip if src_ip != internal_ip else dst_ip
        target_port = dst_port if src_ip != internal_ip else src_port

        connection_key = (attacker_ip, target_port)

        # Initialize or update the connection data
        if connection_key not in connections:
            connections[connection_key] = {"tcp_flags": [tcp_flag], "status": "Closed", "src_port": src_port, "dst_ports": [dst_port], "timestamp": time.time()}
        else:
            connections[connection_key]["tcp_flags"].append(tcp_flag)
            if dst_port not in connections[connection_key]["dst_ports"]:
                connections[connection_key]["dst_ports"].append(dst_port)


if __name__ == '__main__':
    interfaces = get_interfaces()
    selected_interface = choose_interface(interfaces)
    print(f"Sniffing on interface: {selected_interface}")

    internal_ip = get_internal_ip()

    # Start the periodic scan detection in a separate thread
    periodic_scan_detection_partial = partial(periodic_scan_detection, internal_ip, selected_interface)
    detection_thread = threading.Thread(target=periodic_scan_detection_partial)
    detection_thread.daemon = True  # This makes the thread exit when the main program exits
    detection_thread.start()

    # Start sniffing
    monitor_packet_internal_ip = partial(monitor_packet, internal_ip)
    sniff(prn=monitor_packet_internal_ip, store=0, iface=selected_interface)  # Start capturing packets on the chosen interface
