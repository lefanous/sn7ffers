from src.utils.ascii import ascii_art
import time
import os

def print_header(internal_ip, interface):
    print(ascii_art)
    print(f"Sniffing on interface: {interface}")
    print(f"Internal IP: {internal_ip}")
    print("=================================")
    
def print_detection_line(scanner, src, ports, status, timestamp):
    print(f'[{time.ctime(timestamp)}] {scanner} scan from {src[0]} | Ports: {ports} | Status: {status} |')
    
def print_scan_detection(connections, scanner_patterns, pattern_match):
    for src, data in connections.items():
        for pattern, name, status in scanner_patterns:
            if(pattern_match(data["tcp_flags"], pattern)):
                print_detection_line(name, src, data["dst_ports"], status, data["timestamp"])

def periodic_scan_detection(internal_ip, interface, connections, scanner_patterns, pattern_match):
    while True:
        os.system("clear")
        print_header(internal_ip, interface)
        print_scan_detection(connections, scanner_patterns, pattern_match)
        time.sleep(1)

