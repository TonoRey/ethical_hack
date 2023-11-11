#!/usr/bin/env python
from netfilterqueue import NetfilterQueue
from scapy.all import IP, Raw  # Importamos Raw aquí

def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(Raw):
        payload = scapy_packet[Raw].load
        print("Payload:")
        print(payload)
    packet.accept()

queue = NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
