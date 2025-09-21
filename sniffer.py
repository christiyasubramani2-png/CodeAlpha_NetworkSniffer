from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def show_packet(packet):
    if packet.haslayer(IP):
        ip = packet[IP]
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else str(ip.proto)
        print(f"{ip.src} -> {ip.dst} | Protocol: {proto}")

sniff(filter="tcp or udp", prn=show_packet)