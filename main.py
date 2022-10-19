from time import sleep

from scapy.all import *
import scapy.all as scapy
from scapy.layers.inet import IP, ICMP, Ether
from scapy.layers.l2 import ARP


from router import Router
from wire import Wire
from interface import Interface

i1 = Interface('172.16.1.1', 30)
i2 = Interface('172.16.1.2', 30)
i3 = Interface('172.16.10.1', 30)
i4 = Interface('172.16.10.2', 30)


wire = Wire()
wire2 = Wire()

i2.connect_wire(wire)
i1.connect_wire(wire)

i3.connect_wire(wire2)
i4.connect_wire(wire2)

r1 = Router('r1', 501)
r2 = Router('r2', 502)
r3 = Router('r3', 503)

r1.add_interface(i1)
r1.add_interface(i3)

r2.add_interface(i2)
r3.add_interface(i4)

r1.set_bgp('172.16.1.1', 'On', 502, '172.16.1.2')
#r1.set_bgp('172.16.10.1', 'On', 503, '172.16.10.2')
r2.set_bgp('172.16.1.2', 'On', 501, '172.16.1.1')
#r3.set_bgp('172.16.10.2', 'On', 501, '172.16.10.1')

control_list = []
control_list.append(r1.on())
control_list.append(r2.on())
control_list.append(r3.on())

c = 0
while True:
    c += 1
    if c > 2000:
        break

    sleep(1)

r1.off()
r2.off()
r3.off()

for i in control_list:
    i.join()


def test_send():
    packet = IP(dst="8.8.8.8", ttl=20) / ICMP()
    #Ether()/IP()/TCP()
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24")
    answer, pp = scapy.sr(packet, timeout=20)
    for s, r in answer:
        if r.haslayer(IP):
            resp = IP(raw(r))
            print(export_object(resp))
