import threading
from time import sleep
from random import randint
from scapy.layers.inet import IP, ICMP, Ether, TCP

from bgproute import BGPRoute
from route import Route
from tools import ip_to_int, int_to_ip, debug_message


class Router:
    def __init__(self, name, as_id=None):
        self.name = name
        self.as_id = as_id

        self.interfaces = {}
        self.bgp = {}
        self.sockets = {}

        self.state = 0
        self.th_main_thread = None

        self.routing_table_lock = threading.Lock()
        self.routing_table = []

        self.bgp_routing_table_lock = threading.Lock()
        self.bgp_routing_table = []

        self.propagated_bgp_networks = []

    def get_route(self, ip):
        if isinstance(ip, str):
            ip = ip_to_int(ip)
        found_route = None

        with self.routing_table_lock:
            current_table = self.routing_table

        for r in current_table:
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

    def add_bgp_route(self, network, mask, next_hop, as_path, source):
        with self.bgp_routing_table_lock:
            self.bgp_routing_table.append(BGPRoute(network, mask, next_hop, ' '.join(map(str, as_path)), source=source))

    def set_bgp(self, b):
        if b.my_ip in self.interfaces:
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
        debug_message(5, f"Router {self.name}", "on", "Starting...")
        self.state = 1

        for key, i in self.interfaces.items():
            i.on()

        debug_message(5, f"Router {self.name}", "on", "Interfaces started.")

        self.th_main_thread = threading.Thread(target=self.main_thread)
        self.th_main_thread.start()

        debug_message(5, f"Router {self.name}", "on", "Main thread started.")

        for key, b in self.bgp.items():
            b.on()

        debug_message(5, f"Router {self.name}", "on", "BGP instances initialised.")

    def add_route(self, r1):
        to_remove = None
        for key in range(len(self.routing_table)):
            r2 = self.routing_table[key]
            if r1.network == r2.network and r1.mask == r2.mask and r1.metric == r2.metric:
                if r2.source == 'B' and r1.source == 'B':
                    if len(r1.bgp_route.path) == len(r2.bgp_route.path) or len(r1.bgp_route.path) > len(r2.bgp_route.path):
                        return False
                    else:
                      to_remove = key
                elif r1.gw == r2.gw:
                    return False
        if to_remove:
            with self.routing_table_lock:
                self.routing_table.pop(to_remove)

        with self.routing_table_lock:
            self.routing_table.append(r1)

        return True

    def drop_route(self, bgp_route):
        with self.routing_table_lock:
            for i in range(len(self.routing_table)):
                r = self.routing_table[i]
                if r.source == 'B':
                    if r.bgp_route and r.bgp_route == bgp_route:
                        self.routing_table.pop(i)
                        return

    def receive_withdraw_route(self, network, mask, as_id):
        debug_message(3, f"Router {self.name}", "receive_withdraw_route", f"Withdraw message received: {int_to_ip(network)}, {int_to_ip(mask)}, source: {as_id}")
        with self.bgp_routing_table_lock:
            to_del = []
            for i in range(len(self.bgp_routing_table)):
                r = self.bgp_routing_table[i]
                if r.network == network and r.mask == mask and r.source == as_id:
                    to_del.append(i)

            for i in to_del:
                r = self.bgp_routing_table[i]
                self.bgp_routing_table.pop(i)
                self.send_withdraw_route(r)
                self.drop_route(r)

    def send_withdraw_route(self, bgp_route):
        for key, b in self.bgp.items():
            if b.state != 'ESTABLISHED' or b.neighbour_as == bgp_route.source:
                continue

            b.withdraw_route(bgp_route)

    def drop_bgp_routes(self, bgp_as):
        with self.bgp_routing_table_lock:
            to_del = []
            for i in range(len(self.bgp_routing_table)):
                r = self.bgp_routing_table[i]

                if r.source == bgp_as:
                    to_del.append(i)
                    self.drop_route(r)
                    self.send_withdraw_route(r)

            for i in to_del:
                self.bgp_routing_table.pop(i)

    def main_thread(self):
        bgps_in_error_state = {}
        disabled_bgps = {}

        while self.state:
            best_bgp_routes = self.get_best_bgp_routes()

            for key, bgp_route in best_bgp_routes.items():
                self.add_route(Route(bgp_route.network, bgp_route.mask, bgp_route.next_hop, 'B', bgp_route=bgp_route))

            for key, b in self.bgp.items():
                if b.my_ip in disabled_bgps:
                    continue

                if b.state == 'ERROR':
                    if b.my_ip in bgps_in_error_state:
                        bgps_in_error_state[b.my_ip]['count'] += 1
                    else:
                        bgps_in_error_state[b.my_ip] = {
                            'bgp_route': b,
                            'count': 1
                        }

                    if bgps_in_error_state[b.my_ip]['count'] < 2:
                        debug_message(3, f"Router {self.name}", "main_thread", f"BGP is in error state. IP {b.my_ip}, AS {b.neighbour_as}.")
                        debug_message(3, f"Router {self.name}", "main_thread", f"Restarting BGP instance. IP {b.my_ip}, AS {b.neighbour_as}.")
                        b.off()
                        b.on()
                    else:
                        debug_message(3, f"Router {self.name}", "main_thread",
                                      f"BGP is in error state for a long time. IP {b.my_ip}, AS {b.neighbour_as}.")
                        disabled_bgps[b.my_ip] = b
                        self.drop_bgp_routes(b.neighbour_as)
                        debug_message(3, f"Router {self.name}", "main_thread", f"Disabling BGP instance. IP {b.my_ip}, AS {b.neighbour_as}.")
                elif b.state == 'ESTABLISHED':
                    if b.my_ip in bgps_in_error_state:
                        bgps_in_error_state.pop(b.my_ip)

                    b.add_internal_routes(self.propagated_bgp_networks)
                    b.add_shared_routes(best_bgp_routes.values())

            msg = ''
            if len(self.routing_table):
                msg = f"Routing table: \n"
                msg += f"AS   Source  Network  Mask Gateway   Interface AS-PATH\n"
            for r in self.routing_table:
                as_path = ''
                if r.bgp_route:
                    as_path = ' '.join(map(str, r.bgp_route.path))
                msg += f"{self.as_id}   {r.source}  {int_to_ip(r.network)}  {int_to_ip(r.mask)} {int_to_ip(r.gw)}   {int_to_ip(r.interface)}    {as_path} \n"
            if len(self.routing_table):
                debug_message(4, f"Router {self.name}", "main_thread", msg)

            sleep(10)

    def send_data(self, packet):
        if packet[IP].src in self.interfaces:
            self.interfaces[packet[IP].src].send_data(packet)
        # check TTL
        # determine interface by using routing table
        # send data

    def off(self):
        self.state = 0
        debug_message(5, f"Router {self.name}", "off", "Shutting down...")

        for key, b in self.bgp.items():
            b.off()
        debug_message(5, f"Router {self.name}", "off", "BGP instances disabled.")

        for key, i in self.interfaces.items():
            i.off()

        for key, i in self.interfaces.items():
            i.t_thread.join()

        debug_message(5, f"Router {self.name}", "off", "Interfaces disabled.")

        self.th_main_thread.join()

        debug_message(5, f"Router {self.name}", "off", "Router shut down.")
