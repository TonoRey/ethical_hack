#!/usr/bin/env python3
import netfilterqueue

def process_packet(packet):
    try:
        # Convierte el paquete en una cadena de bytes para manipularlo
        pkt = packet.get_payload()
        # Aquí puedes realizar cualquier manipulación o análisis que desees en el paquete.
        # Por ejemplo, puedes imprimir el contenido del paquete:
        print(pkt)
        # Asegúrate de llamar a packet.accept() o packet.drop() al final del procesamiento para permitir o bloquear el paquete.
        packet.drop()
    except Exception as e:
        print(f"Error: {e}")

try:
    queue = netfilterqueue.NetfilterQueue()
    print("Empieza el programa")
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("Saliendo del programa.")
