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

# Get the internal IP address
internal_ip = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr'] 

# Initialize dictionaries to store captured data
connections = {}
result = {}

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

def monitor_packet(pkt):
    if IP in pkt and TCP in pkt:  # Check if the packet is an IP and TCP packet
        src_ip = pkt[IP].src  # Get the source IP address from the packet
        dst_ip = pkt[IP].dst  # Get the destination IP address from the packet
        dst_port = pkt[TCP].dport  # Get the destination port from the packet
        if dst_port == 443:
            return
        src_port = pkt[TCP].sport  # Get the source port from the packet
        tcp_flag = pkt[TCP].flags  # Get the TCP flags from the packet

        # Define the key for the captured data dictionary
        connection_key = src_ip if src_ip != internal_ip else dst_ip

        # Initialize or update the connection data
        if connection_key not in connections:
            connections[connection_key] = {"tcp_flags": [tcp_flag], "status": "Closed", "src_port": src_port, "dst_ports": [dst_port]}
        else:
            connections[connection_key]["tcp_flags"].append(tcp_flag)
            connections[connection_key]["dst_ports"].append(dst_port)

        # Scanner detection patterns
        angryip_open_pattern = ['S', 'RA', 'S', 'SA', 'A', 'RA']
        angryip_closed_pattern = ['S', 'RA', 'S', 'RA']
        masscan_open_pattern = ['S', 'SA', 'R', 'R']
        masscan_closed_pattern = ['S', 'RA', 'R']
        nmap_zmap_open_pattern = ['S', 'SA', 'R']
        nmap_zmap_closed_pattern = ['S', 'RA']


        # Print the captured data
        #os.system('clear')  # Clear the terminal screen
        for src, data in connections.items():
            
        # Scanner detection
            if pattern_match(connections[connection_key]["tcp_flags"], angryip_open_pattern):
                print(f'Angry IP scanner detected on Src_IP: {src} | Dst/Src_Port: {data["dst_ports"]} | Status: Open')
            elif pattern_match(connections[connection_key]["tcp_flags"], angryip_closed_pattern):
                print(f'Angry IP scanner detected on Src_IP: {src} | Dst/Src_Port: {data["dst_ports"]} | Status: Closed')
            elif pattern_match(connections[connection_key]["tcp_flags"], masscan_open_pattern):
                print(f'Masscan scan detected on Src_IP: {src} | Dst/Src_Port: {data["dst_ports"]} | Status: Open')
            elif pattern_match(connections[connection_key]["tcp_flags"], masscan_closed_pattern):
                print(f'Masscan scan detected on Src_IP: {src} | Dst/Src_Port: {data["dst_ports"]} | Status: Closed')
            elif pattern_match(connections[connection_key]["tcp_flags"], nmap_zmap_open_pattern):
                print(f'Nmap/zmap scanner detected on Src_IP: {src} | Dst/Src_Port: {data["dst_ports"]} | Status: Open')
            elif pattern_match(connections[connection_key]["tcp_flags"], nmap_zmap_closed_pattern):
                print(f'Nmap/zmap scanner detected on Src_IP: {src} | Dst/Src_Port: {data["dst_ports"]} | Status: Closed')

def get_interfaces():
    return get_if_list()

ascii_art = r'''
   _____    _____________              
  / ___/___/__  / __/ __/__  __________
  \__ \/ __ \/ / /_/ /_/ _ \/ ___/ ___/
 ___/ / / / / / __/ __/  __/ /  (__  ) 
/____/_/ /_/_/_/ /_/  \___/_/  /____/  
                                       
'''

# Print the ASCII art



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

if __name__ == '__main__':
    interfaces = get_interfaces()
    selected_interface = choose_interface(interfaces)
    print(f"Sniffing on interface: {selected_interface}")
    sniff(prn=monitor_packet, store=0, iface=selected_interface)  # Start capturing packets on the chosen interface
