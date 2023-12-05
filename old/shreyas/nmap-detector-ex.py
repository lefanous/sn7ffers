#install pcapy with "pip install pcapy" before running the script

import pcapy
import re

def is_nmap_scan(packet):
    try:
        data = packet[1].to_bytes()
        data_str = data.decode(errors='ignore')

        # Check for common Nmap signatures in packet payload
        if re.search(r'-s[STUFP]', data_str) or re.search(r'Nmap Scan', data_str):
            return True
    except Exception as e:
        pass

    return False

def main(interface):
    # Create a capture object to listen on the specified interface
    capture = pcapy.open_live(interface, 65536, True, 100)

    print(f"Listening on interface {interface} for Nmap scans...")

    while True:
        header, packet = capture.next()

        if is_nmap_scan(packet):
            print("Detected Nmap scan!")
            print(f"Packet content: {packet}")
            # You can take further actions here, like logging the incident or notifying an administrator.

if __name__ == "__main__":
    interface = "eth0"  # Change this to the appropriate network interface
    main(interface)
