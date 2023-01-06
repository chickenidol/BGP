from time import sleep

from scapy.all import *
import scapy.all as scapy
from scapy.layers.inet import IP, ICMP, Ether
from scapy.layers.l2 import ARP
from router import Router
from wire import Wire
from interface import Interface
from bgp import BGP

# Routers
r1 = Router('r1', 501)
r2 = Router('r2', 502)

# Interfaces
r1_i1 = Interface('10.0.1.1', 24)
r1.add_interface(r1_i1)

r2_i1 = Interface('10.0.1.2', 24)
r2.add_interface(r2_i1)

# Wires
wire1 = Wire()
r1_i1.connect_wire(wire1)
r2_i1.connect_wire(wire1)

bgp_501 = BGP(501, 502, '10.0.1.1', '10.0.1.2')
bgp_502 = BGP(502, 501, '10.0.1.2', '10.0.1.1')

r1.set_bgp(bgp_501)
r2.set_bgp(bgp_502)

# Start the routers
r1.on()
r2.on()

c = 0
while True:
    c += 1
    if c > 2000:
        break

    sleep(1)

r1.off()
r2.off()

def test_send():
    packet = IP(dst="8.8.8.8", ttl=20) / ICMP()
    #Ether()/IP()/TCP()
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24")
    answer, pp = scapy.sr(packet, timeout=20)
    for s, r in answer:
        if r.haslayer(IP):
            resp = IP(raw(r))
            print(export_object(resp))
