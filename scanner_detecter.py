#/usr/bin/env python3

import threading
import time

from scapy.all import *
from functools import partial
from src.utils.scanner_signatures import scanner_signatures, signature_match
from src.utils.interface import get_interfaces, get_internal_ip, choose_interface
from src.utils.print import periodic_scan_detection
from src.utils.packets import extract_packet_info

connections = {} # Initialize dictionaries to store captured data
MAX_TIME_THRESHOLD = 1 # Maximum time gap between packets in a connection

def monitor_packet(internal_ip, packet):
    pkt = extract_packet_info(packet)

    if pkt is None:
        return
    
    current_time = time.time()
    
    attacker_ip = pkt["src_ip"] if pkt["src_ip"] != internal_ip else pkt["dst_ip"]
    target_port = pkt["dst_port"] if pkt["src_ip"] != internal_ip else pkt["src_port"]

    connection_key = (attacker_ip, target_port, int(current_time / MAX_TIME_THRESHOLD))

    if connection_key not in connections or current_time - connections[connection_key]["timestamp"] > MAX_TIME_THRESHOLD:
        connections[connection_key] = {"tcp_flags": [(pkt["tcp_flag"], pkt["window_size"])],
                                       "status": "Closed",
                                       "src_port": pkt["src_port"],
                                       "dst_ports": [pkt["dst_port"]],
                                       "timestamp": current_time}
    else:
        connections[connection_key]["tcp_flags"].append((pkt["tcp_flag"], pkt["window_size"]))
        connections[connection_key]["timestamp"] = current_time

        if pkt["dst_port"] not in connections[connection_key]["dst_ports"]:
            connections[connection_key]["dst_ports"].append(pkt["dst_port"])

if __name__ == '__main__':
    interfaces = get_interfaces()
    selected_interface = choose_interface(interfaces)
    internal_ip = get_internal_ip()

    # Start the periodic scan detection in a separate thread
    periodic_scan_detection_partial = partial(periodic_scan_detection, internal_ip, selected_interface, connections, scanner_signatures, signature_match)
    detection_thread = threading.Thread(target=periodic_scan_detection_partial)
    detection_thread.daemon = True  # This makes the thread exit when the main program exits
    detection_thread.start()

    # Start sniffing
    monitor_packet_internal_ip = partial(monitor_packet, internal_ip)
    sniff(prn=monitor_packet_internal_ip, store=0, iface=selected_interface)  # Start capturing packets on the chosen interface
