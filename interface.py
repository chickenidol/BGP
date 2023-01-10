import threading
from time import sleep
from random import randint
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, ICMP, Ether
from scapy.all import *

from tools import export_scapy


class Interface:
    def __init__(self, ip, mask):
        self.__router = None
        self.__wire = None
        self.__arp_table = {}
        self.__cache = []
        self.__th_main = None

        self.mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                random.randint(0, 255),
                                                random.randint(0, 255))
        self.ip = ip
        self.mask = mask
        self.state = 0

    def __automate(self):
        packet = self.__wire.pop(self.mac)

        if packet:
            if packet.haslayer(ARP):
                if packet[ARP].op == 1:
                    if packet.pdst == self.ip:
                        reply = ARP(op=2, hwsrc=self.mac, psrc=self.ip, pdst=packet[ARP].psrc, hwdst=packet[ARP].hwsrc)
                        full_packet = Ether(dst=packet[ARP].hwsrc, src=self.mac) / reply
                        self.__wire.push(full_packet)
                elif packet[ARP].op == 2:
                    self.__arp_table[packet[ARP].psrc] = packet[ARP].hwsrc

            else:
                self.__router.receive_data(self, packet)

        # iterate through __cache, send stored packets
        tmp = []
        for i in range(len(self.__cache)):
            packet = self.__cache[i]
            if packet['IP'].dst in self.__arp_table:
                full_packet = Ether(src=self.mac, dst=self.__arp_table[packet.dst]) / packet
                self.__wire.push(full_packet)
            else:
                tmp.append(self.__cache[i])
        self.__cache = tmp

    def __main_thread(self):
        while self.state:
            if not self.__wire:
                sleep(2)
                continue

            self.__automate()
            sleep(0.1)

    def on(self):
        self.state = 1
        self.__th_main = threading.Thread(target=self.__main_thread)
        self.__th_main.start()

    def off(self):
        self.state = 0
        self.__th_main.join()

    def install(self, d):
        self.__router = d

    def connect_wire(self, w):
        self.__wire = w

    def send_data(self, packet):
        if packet.dst not in self.__arp_table:
            arp = Ether(src=self.mac, dst=ETHER_BROADCAST) / ARP(op=1, hwsrc=self.mac, psrc=self.ip, pdst=packet.dst)
            self.__wire.push(arp)
            self.__cache.append(packet)
        else:
            full_packet = Ether(src=self.mac, dst=self.__arp_table[packet.dst]) / packet
            self.__wire.push(full_packet)
