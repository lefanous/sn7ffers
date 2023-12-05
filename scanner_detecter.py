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
import os
import threading
import socket
import time
import netifaces as ni

ascii_art = r'''
   _____    _____________              
  / ___/___/__  / __/ __/__  __________
  \__ \/ __ \/ / /_/ /_/ _ \/ ___/ ___/
 ___/ / / / / / __/ __/  __/ /  (__  ) 
/____/_/ /_/_/_/ /_/  \___/_/  /____/  
                                       
'''

scanner_patterns = [
    (['S', 'RA', 'S', 'SA', 'A', 'RA'], 'Angry IP scanner', 'Open'),
    (['S', 'RA', 'S', 'RA'], 'Angry IP scanner', 'Closed'),
    (['S', 'SA', 'R', 'R'], 'Masscan', 'Open'),
    (['S', 'RA', 'R'], 'Masscan', 'Closed'),
    (['S', 'SA', 'R'], 'Nmap/zmap scanner', 'Open'),
    (['S', 'RA'], 'Nmap/zmap scanner', 'Closed'),
]

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

# def pattern_match(flag_sequence, pattern):
#     """
#     Checks if the given pattern of flags appears in the flag_sequence.
#     :param flag_sequence: A list of TCP flags in the order they were captured.
#     :param pattern: A list of TCP flags representing a scanner signature.
#     :return: True if the pattern is found in flag_sequence, False otherwise.
#     """
#     pattern_len = len(pattern)
#     for i in range(len(flag_sequence) - pattern_len + 1):
#         if flag_sequence[i:i + pattern_len] == pattern:
#             return True
#     return False

def pattern_match(flag_sequence, pattern):
    """
    Checks if the given pattern of flags matches the flag_sequence or a significant part of it.
    :param flag_sequence: A list of TCP flags in the order they were captured.
    :param pattern: A list of TCP flags representing a scanner signature.
    :return: True if the pattern matches a significant part of flag_sequence, False otherwise.
    """
    pattern_len = len(pattern)
    sequence_len = len(flag_sequence)

    # Adjust this threshold based on how specific you want the match to be
    # For example, 0.7 means 70% of the pattern should match
    match_threshold = 1.0

    # Iterate over the flag_sequence
    for i in range(sequence_len - pattern_len + 1):
        # Count the number of matching flags
        match_count = sum(1 for j in range(pattern_len) if flag_sequence[i + j] == pattern[j])

        # Check if the match_count meets the threshold
        if match_count / pattern_len >= match_threshold:
            return True

    return False


def print_detection_line(scanner, src, ports, status, timestamp):
    print(f'New scan detection at {time.ctime(timestamp)}')
    print(f'{scanner} scan detected from source IP: {src[0]} on port: {src[1]} | Ports: {ports} | Status: {status}')
    print("=================================")

def print_scan_detection():
    for src, data in connections.items():
        for pattern, name, status in scanner_patterns:
            if(pattern_match(data["tcp_flags"], pattern)):
                print_detection_line(name, src, data["dst_ports"], status, data["timestamp"])

def get_interfaces():
    return get_if_list()

def choose_interface(interfaces):
    print(ascii_art)
    for i, iface in enumerate(interfaces):
        print(f"{i}. {iface}")
    choice = input("Select the interface to sniff (number): ")
    try:
        selected_interface = interfaces[int(choice)]
        return selected_interface
    except (IndexError, ValueError):
        print("Invalid selection. Please select a valid interface number.")
        return choose_interface(interfaces)

def periodic_scan_detection(internal_ip, interface):
    while True:
        os.system("clear")
        print(ascii_art)
        print(f"Sniffing on interface: {interface}")
        print(f"Internal IP: {internal_ip}")
        print("=================================")
        print_scan_detection()
        time.sleep(1)

def get_internal_ip():
    try:
        # Create a socket to connect to an external site
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Use Google's public DNS server to find our IP
            # No actual connection is made, so the target address can be anything
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        print(f"Error obtaining internal IP: {e}")
        return None

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
