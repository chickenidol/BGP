import threading
from time import sleep
from random import randint
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, ICMP, Ether
from scapy.all import *


class Interface:
    def __init__(self, ip, mask):
        self.device = None
        self.mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                             random.randint(0, 255),
                             random.randint(0, 255))
        self.ip = ip
        self.mask = mask
        self.state = 0
        self.wire = None
        self.arp_table = {}
        self.cache = []
        self.t_thread = None

    def install(self, d):
        self.device = d

    def connect_wire(self, w):
        self.wire = w

    def export_scapy(self, obj):
        import zlib
        return bytes_base64(zlib.compress(six.moves.cPickle.dumps(obj, 2), 9))

    def send_data(self, packet):
        if packet.dst not in self.arp_table:
            arp = Ether(src=self.mac, dst=ETHER_BROADCAST) / ARP(op=1, hwsrc=self.mac, psrc=self.ip, pdst=packet.dst)
            self.wire.push(arp)
            self.cache.append(self.export_scapy(packet))
        else:
            full_packet = Ether(src=self.mac, dst=self.arp_table[packet.dst]) / packet
            self.wire.push(full_packet)

    def automate(self):
        packet = self.wire.pop(self.mac)

        if packet:
            if packet.haslayer(ARP):
                if packet[ARP].op == 1:
                    if packet.pdst == self.ip:
                        reply = ARP(op=2, hwsrc=self.mac, psrc=self.ip, pdst=packet[ARP].psrc, hwdst=packet[ARP].hwsrc)
                        full_packet = Ether(dst=packet[ARP].hwsrc, src=self.mac) / reply
                        self.wire.push(full_packet)
                elif packet[ARP].op == 2:
                    self.arp_table[packet[ARP].psrc] = packet[ARP].hwsrc

            else:
                self.device.receive_data(self, packet)

        # iterate through cache, send stored packets
        tmp = []
        for i in range(len(self.cache)):
            packet = import_object(self.cache[i])
            if packet['IP'].dst in self.arp_table:
                full_packet = Ether(src=self.mac, dst=self.arp_table[packet.dst]) / packet
                self.wire.push(full_packet)
            else:
                tmp.append(self.cache[i])
        self.cache = tmp

    def main_thread(self):
        while self.state:
            if not self.wire:
                sleep(2)
                continue

            self.automate()
            sleep(0.1)

    def on(self):
        self.state = 1
        self.t_thread = threading.Thread(target=self.main_thread)
        self.t_thread.start()

    def off(self):
        self.state = 0
