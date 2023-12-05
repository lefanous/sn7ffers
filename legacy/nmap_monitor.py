'''
from scapy.all import *
import netifaces as ni
ip = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
print(f'My IP: {ip}')

# When performing an nmap scan on one specific port, it looks like a request is always sent to port 80 and 443
# and then the request is sent to the port being scanned.
# Therefore I look for at least 3 requests from a src ip 

packets_from_src_ips = {} #dict of all the different packets from different ip's

def monitor_nmap_scans(packet):
    '''Callback function that is called every time a packet arrives'''
    #port80 = False
    #port443 = False
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    dst_port = packet[TCP].dport

    if dst_ip == ip:
        if src_ip not in packets_from_src_ips.keys():  #hmm all requests are saved in the list also the legit ones.. 
            packets_from_src_ips[src_ip] = {} #create empty list to contain the packets from that ip
            #packets_from_src_ips[src_ip].append(packet)
        if dst_port not in packets_from_src_ips[src_ip]:
            packets_from_src_ips[src_ip][dst_port] = {"packet": packet, "count": 0}

        packets_from_src_ips[src_ip][dst_port]["count"] += 1 #should only be syn packets???

        os.system('clear')

        for src_ip, vals in packets_from_src_ips.items():
            for dst_port, dictvals in vals.items():
                print(f'SrcIP: {src_ip} - Port: {dst_port} - Count: {dictvals["count"]}')

sniff(prn=monitor_nmap_scans, filter="tcp") #only look at tcp packets 
'''



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
ip = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
print(f'My IP: {ip}')
'''TODO I think we should only look at the packets where our ip is the src or dst'''

captured_data = {}  # Initialize an empty dictionary to store captured data

def monitor_packet(pkt):
    src_ip = pkt[IP].src  # Get the source IP address from the packet
    dst_ip = pkt[IP].dst  # Get the destination IP address from the packet
    dst_port = pkt[TCP].dport  # Get the destination port from the packet
    tcp_flags = pkt[TCP].flags  # Get the TCP flags from the packet
    if dst_ip == ip or src_ip == ip:
        if IP in pkt and TCP in pkt:  # Check if the packet is an IP and TCP packet
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
