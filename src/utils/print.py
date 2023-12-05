from src.utils.ascii import ascii_art
import time
import os

def print_header(internal_ip, interface):
    print(ascii_art)
    print(f"Sniffing on interface: {interface}")
    print(f"Internal IP: {internal_ip}")
    print("=================================")
    
def print_detection_line(scanner, src, ports, status, timestamp):
    print(f'New scan detection at {time.ctime(timestamp)}')
    print(f'{scanner} scan detected from source IP: {src[0]} on port: {src[1]} | Ports: {ports} | Status: {status}')
    print("=================================")
    
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

