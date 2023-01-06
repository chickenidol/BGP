from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, ICMP, Ether
from scapy.all import *
import threading
from scapy.utils import rdpcap

from scapy.contrib.bgp import BGPHeader, BGPOpen, BGPUpdate, BGPPathAttr, BGPNLRI_IPv4, BGPPALocalPref, BGPKeepAlive
class Wire:
    def __init__(self):
        self.container = []
        self.data_lock = threading.Lock()

    def export_scapy(self, obj):
        import zlib
        return bytes_base64(zlib.compress(six.moves.cPickle.dumps(obj, 2), 9))

    def push(self, data):
        #if data.haslayer(BGPHeader):
        data.show()
        #wrpcap('filtered.pcap', data, append=True)

        with self.data_lock:
            self.container.append(self.export_scapy(data))

    def pop(self, mac):

        ret_index = None
        with self.data_lock:
            for i in range(len(self.container)):
                # craft Ether packet
                packet = import_object(self.container[i])
                if packet.src != mac:
                    if packet.dst == 'ff:ff:ff:ff:ff:ff' or packet.dst == mac:
                        ret_index = i
                        break

            if ret_index is not None:
                return import_object(self.container.pop(ret_index))

        return None
