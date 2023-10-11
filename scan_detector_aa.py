from scapy.all import *
from datetime import datetime

def list_devices():
    devices = get_if_list()
    for i, device in enumerate(devices):
        print(f"{i}. {device}")
    return devices

def capture_packets(device):
    print(f"Capturing packets on {device}...")

    def packet_callback(packet):
        if packet.haslayer(TCP) and (packet[TCP].sport == 22 or packet[TCP].dport == 22):
            with open("scan_log.txt", "a") as f:
                f.write(f"[{datetime.now()}] {packet.summary()}\n")

            f.write(f"[{datetime.now()}] {packet.summary()}\n")

    sniff(iface=device, prn=packet_callback, store=0)

if __name__ == "__main__":
    devices = list_devices()
    if devices:
        selection = input("Enter the number of the device you want to listen on: ")
        try:
            selected_device = devices[int(selection)]
            capture_packets(selected_device)
        except (ValueError, IndexError):
            print("Invalid selection. Please run the script again and choose a valid number.")
    else:
        print("No devices found.")
