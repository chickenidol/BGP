import threading
from time import sleep
from random import randint
from scapy.layers.inet import IP, ICMP, Ether, TCP

from bgproute import BGPRoute
from route import Route
from tools import ip_to_int, int_to_ip


class Router:
    def __init__(self, name, as_id=None):
        self.name = name
        self.as_id = as_id

        self.interfaces = {}
        self.bgp = {}
        self.sockets = {}

        self.state = 0
        self.th_main_thread = None

        self.routing_table = []

        self.bgp_routing_table_lock = threading.Lock()
        self.bgp_routing_table = []

        self.propagated_bgp_networks = []

    def get_route(self, ip):
        if isinstance(ip, str):
            ip = ip_to_int(ip)
        found_route = None
        for r in self.routing_table:
            if r.if_ip_in(ip):
                if not found_route:
                    found_route = r
                elif r.mask == found_route.mask:
                    if r.metric < found_route.metric:
                        found_route = r
                elif r.mask > found_route.mask:
                    found_route = r
        return found_route

    def get_best_bgp_routes(self):
        store = {}
        with self.bgp_routing_table_lock:
            for r in self.bgp_routing_table:
                key = str(r.network) + "_" + str(r.mask)
                if key not in store:
                    store[key] = r
                else:
                    if len(r.path) < len(store[key].path):
                        store[key] = r

        return store

    def add_bgp_network(self, network, mask):
        network = ip_to_int(network)
        mask = ip_to_int(mask)
        self.propagated_bgp_networks.append((network, mask))

    def add_interface(self, i):
        i.install(self)
        self.interfaces[i.ip] = i
        self.routing_table.append(Route(i.ip, i.mask, '0.0.0.0', 'C', i.ip, 0))

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

    def add_bgp_route(self, network, mask, next_hop, as_path):
        with self.bgp_routing_table_lock:
            self.bgp_routing_table.append(BGPRoute(network, mask, next_hop, ' '.join(map(str, as_path))))

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

    def add_route(self, r1):
        for r2 in self.routing_table:
            if r1.network == r2.network and r1.mask == r2.mask and r1.gw == r2.gw and r1.metric == r2.metric:
                return False

        self.routing_table.append(r1)
        return True

    def main_thread(self):
        while self.state:
            best_bgp_routes = {}

            best_bgp_routes = self.get_best_bgp_routes()

            for key, bgp_route in best_bgp_routes.items():
                self.add_route(Route(bgp_route.network, bgp_route.mask, bgp_route.next_hop, 'B'))

            for key, b in self.bgp.items():
                if b.state == 'ERROR':
                    print(f'BGP {b.my_ip} status ERROR, restarting.')
                    b.off()
                    b.on()
                elif b.state == 'ESTABLISHED':
                    b.add_internal_routes(self.propagated_bgp_networks)
                    b.add_shared_routes(best_bgp_routes.values())

            for r in self.routing_table:
                print(self.as_id, r.source, int_to_ip(r.network), int_to_ip(r.mask), int_to_ip(r.gw))
            sleep(10)

    def send_data(self, packet):
        if packet[IP].src in self.interfaces:
            self.interfaces[packet[IP].src].send_data(packet)
        # check TTL
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
