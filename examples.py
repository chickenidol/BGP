from time import sleep

from scapy.all import *
import scapy.all as scapy
from scapy.layers.inet import IP, ICMP, Ether
from scapy.layers.l2 import ARP
from router import Router
from wire import Wire
from interface import Interface
from bgp import BGP


# two routers, the simplest configuration
def conf1():
    # Routers
    r1 = Router('r1', 501)
    r2 = Router('r2', 502)

    # Interfaces
    r1_i1 = Interface('10.0.1.1', '255.255.255.252')
    r1.add_interface(r1_i1)

    r1_i2 = Interface('20.0.0.254', '255.255.0.0')
    r1.add_interface(r1_i2)
    r1.add_bgp_network('20.0.0.0', '255.255.0.0')

    r2_i1 = Interface('10.0.1.2', '255.255.255.252')
    r2.add_interface(r2_i1)

    r2_i2 = Interface('30.0.0.254', '255.255.0.0')
    r2.add_interface(r2_i2)
    r2.add_bgp_network('30.0.0.0', '255.255.0.0')

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


# three interconnected routers
def conf2():
    # Routers
    r1 = Router('r1', 501)
    r2 = Router('r2', 502)
    r3 = Router('r3', 503)

    # Interfaces
    r1_i1 = Interface('10.0.1.1', '255.255.255.252')
    r1.add_interface(r1_i1)

    r1_i2 = Interface('20.0.0.254', '255.255.0.0')
    r1.add_interface(r1_i2)

    r1_i3 = Interface('12.0.1.1', '255.255.255.252')
    r1.add_interface(r1_i3)

    r1.add_bgp_network('20.0.0.0', '255.255.0.0')

    r2_i1 = Interface('10.0.1.2', '255.255.255.252')
    r2.add_interface(r2_i1)

    r2_i2 = Interface('30.0.0.254', '255.255.0.0')
    r2.add_interface(r2_i2)

    r2_i3 = Interface('11.0.1.2', '255.255.255.252')
    r2.add_interface(r2_i3)

    r2.add_bgp_network('30.0.0.0', '255.255.0.0')


    r3_i1 = Interface('12.0.1.2', '255.255.255.252')
    r3.add_interface(r3_i1)

    r3_i2 = Interface('40.0.255.254', '255.0.0.0')
    r3.add_interface(r3_i2)

    r3_i3 = Interface('11.0.1.1', '255.255.255.252')
    r3.add_interface(r3_i3)

    r3.add_bgp_network('40.0.0.0', '255.0.0.0')

    # Wires
    wire1 = Wire()
    r1_i1.connect_wire(wire1)
    r2_i1.connect_wire(wire1)

    wire2 = Wire()
    r1_i3.connect_wire(wire2)
    r3_i1.connect_wire(wire2)

    wire3 = Wire()
    r3_i3.connect_wire(wire3)
    r2_i3.connect_wire(wire3)

    bgp_501_1 = BGP(501, 502, '10.0.1.1', '10.0.1.2')
    bgp_501_2 = BGP(501, 503, '12.0.1.1', '12.0.1.2')

    bgp_502_1 = BGP(502, 501, '10.0.1.2', '10.0.1.1')
    bgp_502_2 = BGP(502, 503, '11.0.1.2', '11.0.1.1')

    bgp_503_1 = BGP(503, 501, '12.0.1.2', '12.0.1.1')
    bgp_503_2 = BGP(503, 502, '11.0.1.1', '11.0.1.2')

    r1.set_bgp(bgp_501_1)
    r1.set_bgp(bgp_501_2)

    r2.set_bgp(bgp_502_1)
    r2.set_bgp(bgp_502_2)

    r3.set_bgp(bgp_503_1)
    r3.set_bgp(bgp_503_2)

    # Start the routers
    r1.on()
    r2.on()
    r3.on()
    c = 0
    while True:
        c += 1
        if c > 2000:
            break

        sleep(1)

    r1.off()
    r2.off()
    r3.off()

# three interconnected routers, one stops in 10 sec to demonstrate KEEPALIVE functionality
def conf3():
    # Routers
    r1 = Router('r1', 501)
    r2 = Router('r2', 502)
    r3 = Router('r3', 503)

    # Interfaces
    r1_i1 = Interface('10.0.1.1', '255.255.255.252')
    r1.add_interface(r1_i1)

    r1_i2 = Interface('20.0.0.254', '255.255.0.0')
    r1.add_interface(r1_i2)

    r1_i3 = Interface('12.0.1.1', '255.255.255.252')
    r1.add_interface(r1_i3)

    r1.add_bgp_network('20.0.0.0', '255.255.0.0')

    r2_i1 = Interface('10.0.1.2', '255.255.255.252')
    r2.add_interface(r2_i1)

    r2_i2 = Interface('30.0.0.254', '255.255.0.0')
    r2.add_interface(r2_i2)

    r2_i3 = Interface('11.0.1.2', '255.255.255.252')
    r2.add_interface(r2_i3)

    r2.add_bgp_network('30.0.0.0', '255.255.0.0')

    r3_i1 = Interface('12.0.1.2', '255.255.255.252')
    r3.add_interface(r3_i1)

    # r3_i1 and r1_i3

    r3_i2 = Interface('40.0.255.254', '255.0.0.0')
    r3.add_interface(r3_i2)

    r3_i3 = Interface('11.0.1.1', '255.255.255.252')
    r3.add_interface(r3_i3)
    # r3_i3 and r2_i3

    r3.add_bgp_network('40.0.0.0', '255.0.0.0')

    # Wires
    wire1 = Wire()
    r1_i1.connect_wire(wire1)
    r2_i1.connect_wire(wire1)

    wire2 = Wire()
    r1_i3.connect_wire(wire2)
    r3_i1.connect_wire(wire2)

    wire3 = Wire()
    r3_i3.connect_wire(wire3)
    r2_i3.connect_wire(wire3)

    bgp_501_1 = BGP(501, 502, '10.0.1.1', '10.0.1.2')
    bgp_501_2 = BGP(501, 503, '12.0.1.1', '12.0.1.2')

    bgp_502_1 = BGP(502, 501, '10.0.1.2', '10.0.1.1')
    bgp_502_2 = BGP(502, 503, '11.0.1.2', '11.0.1.1')

    bgp_503_1 = BGP(503, 501, '12.0.1.2', '12.0.1.1')
    bgp_503_2 = BGP(503, 502, '11.0.1.1', '11.0.1.2')

    r1.set_bgp(bgp_501_1)
    r1.set_bgp(bgp_501_2)

    r2.set_bgp(bgp_502_1)
    r2.set_bgp(bgp_502_2)

    r3.set_bgp(bgp_503_1)
    r3.set_bgp(bgp_503_2)

    # Start the routers
    r1.on()
    r2.on()
    r3.on()
    c = 0
    while True:
        c += 1
        if c % 31 == 0:
            r3.off()

        if c % 37 == 0:
            r3.off()

        if c % 53 == 0:
            r3.off()

        sleep(1)

    r1.off()
    r2.off()
    r3.off()

