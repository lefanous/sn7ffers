import os
import socket
import netifaces as ni
from scapy.all import *

ascii_art = r'''
   _____    _____________              
  / ___/___/__  / __/ __/__  __________
  \__ \/ __ \/ / /_/ /_/ _ \/ ___/ ___/
 ___/ / / / / / __/ __/  __/ /  (__  ) 
/____/_/ /_/_/_/ /_/  \___/_/  /____/  
                                       
'''

############## Scanner detection patterns ##############

scanner_patterns = [
    (['S', 'RA', 'S', 'SA', 'A', 'RA'], 'Angry IP scanner', 'Open'),
    (['S', 'RA', 'S', 'RA'], 'Angry IP scanner', 'Closed'),
    (['S', 'SA', 'R', 'R'], 'Masscan', 'Open'),
    (['S', 'RA', 'R'], 'Masscan', 'Closed'),
    (['S', 'SA', 'R'], 'Nmap/zmap scanner', 'Open'),
    (['S', 'RA'], 'Nmap/zmap scanner', 'Closed'),
]

def pattern_match(flag_sequence, pattern):
    """
    Checks if the given pattern of flags appears in the flag_sequence.
    :param flag_sequence: A list of TCP flags in the order they were captured.
    :param pattern: A list of TCP flags representing a scanner signature.
    :return: True if the pattern is found in flag_sequence, False otherwise.
    """
    pattern_len = len(pattern)
    for i in range(len(flag_sequence) - pattern_len + 1):
        if flag_sequence[i:i + pattern_len] == pattern:
            return True
    return False

def periodic_scan_detection(internal_ip, interface):
    while True:
        os.system("clear")
        print(ascii_art)
        print(f"Sniffing on interface: {interface}")
        print(f"Internal IP: {internal_ip}")
        print("=================================")
        print_scan_detection()
        time.sleep(1)

############## Print ##############

def print_detection_line(scanner, src, ports, status, timestamp):
    print(f'New scan detection at {time.ctime(timestamp)}')
    print(f'{scanner} scan detected from source IP: {src[0]} on port: {src[1]} | Ports: {ports} | Status: {status}')
    print("=================================")

def print_scan_detection():
    for src, data in connections.items():
        for pattern, name, status in scanner_patterns:
            if(pattern_match(data["tcp_flags"], pattern)):
                print_detection_line(name, src, data["dst_ports"], status, data["timestamp"])

############## Network Inteface ##############

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