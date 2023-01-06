import threading
from time import sleep
from random import randint
from scapy.layers.inet import IP, ICMP, Ether, TCP

class Router:
    def __init__(self, name, as_id=None):
        self.name = name
        self.as_id = as_id

        self.interfaces = {}
        self.bgp = {}
        self.sockets = {}

        self.state = 0
        self.sessions = {}
        self.sessions_lock = threading.Lock()
        self.th_main_thread = None

    def add_interface(self, i):
        i.install(self)
        self.interfaces[i.ip] = i

    def get_port(self, src_ip, src_port, sock):
        if src_ip not in self.interfaces:
            return False

        if src_ip in self.sockets:
            if src_port in self.sockets[src_ip]:
                return False
            else:
                self.sockets[src_ip][src_port] = sock
                return True
        else:
            self.sockets[src_ip] = {}
            self.sockets[src_ip][src_port] = sock
            return True

    def release_port(self, src_ip, src_port, sock):
        if src_ip in self.sockets:
            if src_port in self.sockets[src_ip]:
                if self.sockets[src_ip][src_port] == sock:
                    del self.sockets[src_ip][src_port]

    def set_bgp(self, b):
        b.install(self)
        self.bgp[b.my_ip] = b

    def receive_data(self, i, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if dst_ip != i.ip:
                # determine a route, send the packet
                print("got routing packet")
            else:
                if packet.haslayer(TCP):
                    dport = packet[TCP].dport
                    if dst_ip in self.sockets:
                        if dport in self.sockets[dst_ip]:
                            s = self.sockets[dst_ip][dport]
                            s.receive_data(packet)

    def on(self):
        self.state = 1

        for key, i in self.interfaces.items():
            i.on()

        self.th_main_thread = threading.Thread(target=self.main_thread)
        self.th_main_thread.start()

        for key, b in self.bgp.items():
            b.on()

    def main_thread(self):
        while self.state:
            for key, b in self.bgp.items():
                if b.state == 'ERROR':
                    print(f'BGP {b.my_ip} status ERROR, restarting.')
                    b.off()
                    b.on()
            sleep(5)

    def send_data(self, packet):
        if packet[IP].src in self.interfaces:
            self.interfaces[packet[IP].src].send_data(packet)

        # determine interface by using routing table
        # send data

    def off(self):
        self.state = 0

        for key, b in self.bgp.items():
            b.off()

        for key, i in self.interfaces.items():
            i.off()

        for key, i in self.interfaces.items():
            i.t_thread.join()

        self.th_main_thread.join()
