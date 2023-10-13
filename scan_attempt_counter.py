#!/usr/bin/env python  

'''
----- README ----
## Objectiv :
use Scapy to sniff the packets arriving to a network interface. After each packet is
captured, we can be then process it using a callback function to get the useful information from it.

## Algorithm:
This script captures packets, tracks how many times a source IP is trying to reach a specific destination IP and port,
and continuously displays this information on the screen.

## How to:
1. import the file to your virtual machine, 
2. open your terminal, cd to the directory containing the source code
3. run command : $chmod +x <file> , to make the file executable
4. run the script with following command: $sudo ./<file>
5. use another/parallel terminal to run your scan as usual. The result should appear in the other terminal ;-)

## Note: 
feel free to ad to this script. i havent reeally made it robust, with error handling yet.
'''

from scapy.all import *  # Import the Scapy library for working with network packets
import os

captured_data = {}  # Initialize an empty dictionary to store captured data

def monitor_packet(pkt):
    if IP in pkt and TCP in pkt:  # Check if the packet is an IP and TCP packet
        src_ip = pkt[IP].src  # Get the source IP address from the packet
        dst_ip = pkt[IP].dst  # Get the destination IP address from the packet
        dst_port = pkt[TCP].dport  # Get the destination port from the packet

        if src_ip not in captured_data:  # If the source IP is not in the captured_data dictionary
            captured_data[src_ip] = {}  # Initialize an empty dictionary for that source IP

        if dst_port not in captured_data[src_ip]:  # If the destination port is not in the source IP's dictionary
            captured_data[src_ip][dst_port] = {"count": 0, "dst_ip": dst_ip, "status":"Closed"}  # Initialize a count and store the destination IP

        captured_data[src_ip][dst_port]["count"] += 1  # Increment the count of attempts

        os.system('clear')  # Clear the terminal screen

        for src_ip, port_counts in captured_data.items():  # Iterate through the source IPs and their port counts
            for port, data in port_counts.items():  # Iterate through the ports and their data
                count = data["count"]  # Get the count of attempts
                dest_ip = data["dst_ip"]  # Get the destination IP
                status = data["status"]
                
                # Check if the port is open (example: using SYN/ACK flag as an indicator)
                # We then check if the port is open based on a simple condition (e.g., if the number of
                # attempts is greater than 1) and update the status accordingly. 
                if status == "Closed" and count > 1:
                    status = "Open"
                    
                print(f'Src_IP: {src_ip} | Dst_IP: {dest_ip} | Dst_Port: {port:5} | Status:{status:8}| Attempts: {count}')  # Print the information

if __name__ == '__main__':
    sniff(prn=monitor_packet, store=0, iface="eth0")  # Start capturing packets and call the monitor_packet function

