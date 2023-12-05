#!/usr/bin/env python

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
import os
import netifaces as ni
internal_ip = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr'] #fix this to match the chosen interface and add a comment that explains

connections = {}  # Initialize an empty dictionary to store captured data

def detect_signature():
	pass


def monitor_packet(pkt):
    if IP in pkt and TCP in pkt:  # Check if the packet is an IP and TCP packet
        src_ip = pkt[IP].src  # Get the source IP address from the packet
        dst_ip = pkt[IP].dst  # Get the destination IP address from the packet
        dst_port = pkt[TCP].dport  # Get the destination port from the packet
        src_port = pkt[TCP].sport  # Get the source port from the packet
        tcp_flag = pkt[TCP].flags  # Get the TCP flags from the packet

        # Define the key for the captured data dictionary
        connection_key = src_ip if src_ip != internal_ip else dst_ip #we only save based on ip from attacker whether it is the src or dst ip

        # Initialize or update the connection data
        if connection_key not in connections:
            connections[connection_key] = {"tcp_flags": [tcp_flag], "status": "Closed", "src_port": src_port, "dst_ports": [dst_port]}
        else:
        	connections[connection_key]["tcp_flags"].append(tcp_flag)
        	connections[connection_key]["dst_ports"].append(dst_port)
        

        # Print the captured data
        os.system('clear')  # Clear the terminal screen
        for src, data in connections.items():
            print(f'Src_IP: {src} | Dst_Port: {data["dst_ports"]} | Status: {data["status"]} | TCP_flags: {data["tcp_flags"]}')

def get_interfaces():
    return get_if_list()

def choose_interface(interfaces):
    for i, iface in enumerate(interfaces):
        print(f"{i}. {iface}")
    choice = input("Select the interface to sniff (number): ")
    try:
        selected_interface = interfaces[int(choice)]
        return selected_interface
    except (IndexError, ValueError):
        print("Invalid selection. Please select a valid interface number.")
        return choose_interface(interfaces)

if __name__ == '__main__':
    interfaces = get_interfaces()
    selected_interface = choose_interface(interfaces)
    print(f"Sniffing on interface: {selected_interface}")
    sniff(prn=monitor_packet, store=0, iface=selected_interface)  # Start capturing packets on the chosen interface
