#i rewrote it to not look at packet from port 80 and 443 and now it is quite similar to the one Alex wrote
# i just only look at the packets with my ip as the dst_ip

from scapy.all import *
import netifaces as ni
ip = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
print(f'My IP: {ip}')

packets_from_src_ips = {} 

def monitor_nmap_scans(packet):
    '''Callback function that is called every time a packet arrives'''
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    dst_port = packet[TCP].dport

    if dst_ip == ip:
        if src_ip not in packets_from_src_ips.keys():  #hmm all requests are saved in the list also the legit ones.. 
            packets_from_src_ips[src_ip] = {} 
        if dst_port not in packets_from_src_ips[src_ip]:
            packets_from_src_ips[src_ip][dst_port] = {"packet": packet, "count": 0}

        packets_from_src_ips[src_ip][dst_port]["count"] += 1 #when is it an attempt?
        #also i only get one attempt per nmap scan (also when using the script from Alex)

        os.system('clear')

        for src_ip, vals in packets_from_src_ips.items():
            for dst_port, dictvals in vals.items():
                print(f'SrcIP: {src_ip} - Port: {dst_port} - Count: {dictvals["count"]}')

sniff(prn=monitor_nmap_scans, filter="tcp")