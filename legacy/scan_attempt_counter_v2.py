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
'''TODO I think we should only look at the packets where our ip is the src or dst'''

captured_data = {}  # Initialize an empty dictionary to store captured data

def monitor_packet(pkt):
    if IP in pkt and TCP in pkt:  # Check if the packet is an IP and TCP packet
        src_ip = pkt[IP].src  # Get the source IP address from the packet
        dst_ip = pkt[IP].dst  # Get the destination IP address from the packet
        dst_port = pkt[TCP].dport  # Get the destination port from the packet
        tcp_flags = pkt[TCP].flags  # Get the TCP flags from the packet

        # Define the key for the captured data dictionary
        connection_key = (src_ip, dst_ip, dst_port)

        # Initialize or update the connection data
        if connection_key not in captured_data:
            captured_data[connection_key] = {"count": 0, "status": "Closed"}

        '''TODO I think we should agree on what is an attempt and what is just communication - if the amount of attemps is relevant'''
        captured_data[connection_key]["count"] += 1  # Increment the count of attempts

        # Check if the TCP flags indicate a SYN-ACK (port is open) or RST (port is closed)
        '''TODO is it not a rst, ack if the port is closed? and make it more robust maybe'''
        print(tcp_flags) 
        if 'S' in tcp_flags and 'A' in tcp_flags:
            captured_data[connection_key]["status"] = "Open"
        elif 'R' in tcp_flags:
            captured_data[connection_key]["status"] = "Closed"

        # Print the captured data
        os.system('clear')  # Clear the terminal screen
        for conn, data in captured_data.items():
            src_ip, dest_ip, port = conn
            print(f'Src_IP: {src_ip} | Dst_IP: {dest_ip} | Dst_Port: {port:5} | Status: {data["status"]:8} | Attempts: {data["count"]}')

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
