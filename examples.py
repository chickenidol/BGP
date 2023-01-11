from time import sleep

from scapy.all import *
import scapy.all as scapy
from scapy.layers.inet import IP, ICMP, Ether
from scapy.layers.l2 import ARP
from router import Router
from tools import cidr_to_netmask
from wire import Wire
from interface import Interface
from bgp import BGP


# helpers
def connect_bgp_routers(nlri1, nlri2, r1, r2):
    net1 = nlri1.split('/')[0]
    net2 = nlri2.split('/')[0]

    i1 = Interface(net1, cidr_to_netmask(nlri1.split('/')[1]))
    i2 = Interface(net2, cidr_to_netmask(nlri2.split('/')[1]))

    wire = Wire()
    i1.connect_wire(wire)
    i2.connect_wire(wire)

    r1.add_interface(i1)
    r2.add_interface(i2)

    r1.set_bgp(BGP(r1.as_id, r2.as_id, net1, net2))
    r2.set_bgp(BGP(r2.as_id, r1.as_id, net2, net1))

    return i1, i2


def add_announced_network(r1, nlri):
    network = nlri.split('/')[0]
    mask = cidr_to_netmask(nlri.split('/')[1])

    i1 = Interface(network, mask)
    r1.add_interface(i1)
    r1.add_bgp_network(network, mask)


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
        if c % 43 == 0:
            r3.on()

        if c % 85 == 0:
            r3.off()

        sleep(1)

    r1.off()
    r2.off()
    r3.off()


# ring of 4 routers
def conf4():
    # Routers
    r501 = Router(501)
    r502 = Router(502)
    r503 = Router(503)
    r504 = Router(504)

    connect_bgp_routers('172.16.1.1/30', '172.16.1.2/30', r501, r502)
    connect_bgp_routers('172.16.2.1/30', '172.16.2.2/30', r502, r503)
    connect_bgp_routers('172.16.3.1/30', '172.16.3.2/30', r503, r504)
    connect_bgp_routers('172.16.4.1/30', '172.16.4.2/30', r501, r504)

    add_announced_network(r501, '10.0.0.0/16')
    add_announced_network(r502, '20.0.0.0/16')
    add_announced_network(r503, '30.0.0.0/16')
    add_announced_network(r504, '40.0.0.0/16')

    # Start the routers
    r501.on()
    r502.on()
    r503.on()
    r504.on()
    c = 0
    while True:
        c += 1
        if c == 30:
            r504.off()

        sleep(1)


# arbitrary configuration of 6 router with router 502 going offline after 100 sec
def conf5():
    # Routers
    r501 = Router(501)
    r502 = Router(502)
    r503 = Router(503)
    r504 = Router(504)
    r505 = Router(505)
    r506 = Router(506)

    connect_bgp_routers('172.16.1.1/30', '172.16.1.2/30', r501, r502)
    connect_bgp_routers('172.16.2.1/30', '172.16.2.2/30', r502, r503)
    connect_bgp_routers('172.16.4.1/30', '172.16.4.2/30', r502, r504)
    connect_bgp_routers('172.16.5.1/30', '172.16.5.2/30', r501, r504)
    connect_bgp_routers('172.16.6.1/30', '172.16.6.2/30', r505, r501)

    connect_bgp_routers('172.16.7.1/30', '172.16.7.2/30', r505, r506)
    connect_bgp_routers('172.16.8.1/30', '172.16.8.2/30', r504, r503)
    connect_bgp_routers('172.16.9.1/30', '172.16.9.2/30', r502, r506)

    add_announced_network(r501, '10.0.0.0/16')
    add_announced_network(r502, '20.0.0.0/16')
    add_announced_network(r503, '30.0.0.0/16')
    add_announced_network(r504, '40.0.0.0/16')
    add_announced_network(r505, '50.0.0.0/16')

    add_announced_network(r506, '61.0.0.0/16')
    add_announced_network(r506, '62.0.0.0/16')

    # Start the routers
    r501.on()
    r502.on()
    r503.on()
    r504.on()
    r505.on()
    r506.on()

    c = 0
    while True:
        c += 1
        if c == 100:
            r502.off()

        sleep(1)


def conf6():
    # Routers
    r501 = Router(501)
    r502 = Router(502)
    r503 = Router(503)
    r504 = Router(504)
    r505 = Router(505)
    r506 = Router(506)
    r507 = Router(507)
    r508 = Router(508)
    r509 = Router(509)
    r510 = Router(510)
    r511 = Router(511)
    r512 = Router(512)

    add_announced_network(r501, '10.0.0.0/16')
    add_announced_network(r502, '20.0.0.0/16')
    add_announced_network(r503, '30.0.0.0/16')
    add_announced_network(r504, '40.0.0.0/16')
    add_announced_network(r505, '50.0.0.0/16')
    add_announced_network(r506, '61.0.0.0/16')
    add_announced_network(r506, '62.0.0.0/16')
    add_announced_network(r507, '70.0.0.0/16')
    add_announced_network(r508, '80.0.0.0/16')
    add_announced_network(r509, '90.0.0.0/16')
    add_announced_network(r510, '100.0.0.0/16')
    add_announced_network(r511, '110.0.0.0/16')

    add_announced_network(r512, '120.0.0.0/16')
    add_announced_network(r512, '121.0.0.0/16')
    add_announced_network(r512, '122.0.0.0/16')
    add_announced_network(r512, '123.0.0.0/16')

    connect_bgp_routers('172.16.1.1/30', '172.16.1.2/30', r501, r502)
    connect_bgp_routers('172.16.2.1/30', '172.16.2.2/30', r502, r503)
    connect_bgp_routers('172.16.4.1/30', '172.16.4.2/30', r502, r504)
    connect_bgp_routers('172.16.5.1/30', '172.16.5.2/30', r501, r504)
    connect_bgp_routers('172.16.6.1/30', '172.16.6.2/30', r505, r501)

    connect_bgp_routers('172.16.7.1/30', '172.16.7.2/30', r505, r506)
    connect_bgp_routers('172.16.8.1/30', '172.16.8.2/30', r504, r503)
    connect_bgp_routers('172.16.9.1/30', '172.16.9.2/30', r502, r506)

    connect_bgp_routers('172.16.10.1/30', '172.16.10.2/30', r507, r508)
    connect_bgp_routers('172.16.11.1/30', '172.16.11.2/30', r507, r509)
    connect_bgp_routers('172.16.12.1/30', '172.16.12.2/30', r507, r510)
    connect_bgp_routers('172.16.13.1/30', '172.16.13.2/30', r507, r511)
    connect_bgp_routers('172.16.14.1/30', '172.16.14.2/30', r507, r512)
    connect_bgp_routers('172.16.15.1/30', '172.16.15.2/30', r507, r506)
    connect_bgp_routers('172.16.16.1/30', '172.16.16.2/30', r511, r506)

    # Start the routers
    r501.on()
    r502.on()
    r503.on()
    r504.on()
    r505.on()
    r506.on()
    r507.on()
    r508.on()
    r509.on()
    r510.on()
    r511.on()
    r512.on()

    c = 0
    while True:
        c += 1
        #if c == 100:
        #    r502.off()

        sleep(10)
