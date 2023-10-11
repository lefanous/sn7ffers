import pcapy
from datetime import datetime

def list_devices():
    devices = pcapy.findalldevs()
    for i, device in enumerate(devices):
        print(f"{i}. {device}")
    return devices

def capture_packets(device):
    cap = pcapy.open_live(device, 65536, True, 100)
    filter = "port 22"
    cap.setfilter(filter)  # Set the filter directly on the pcap object
    
    print(f"Capturing packets on {device}...")
    while True:
        (header, packet) = cap.next()
        if packet is None:
            continue
        
        # Log the packet to a file
        with open("scan_log.txt", "a") as f:
            f.write(f"[{datetime.now()}] {packet}\n")

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
