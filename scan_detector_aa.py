import pcapy
from datetime import datetime

# Set up the packet capture
cap = pcapy.open_live("en0", 65536, True, 100)

# Define the filter to match packets with a source or destination port of 22
filter = "port 22"

# Loop through the captured packets
while True:
    (header, packet) = cap.next()
    if packet is None:
        continue

    # Check if the packet matches the filter
    if filter in str(packet):
        # Log the packet to a file
        with open("scan_log.txt", "a") as f:
            f.write(f"[{datetime.now()}] {packet}\n")
