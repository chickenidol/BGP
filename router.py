import threading
from time import sleep
from random import randint

from scapy.contrib.bgp import BGPKeepAlive
from scapy.layers.inet import IP, ICMP, Ether, TCP

from bgproute import BGPRoute
from route import Route
from tools import ip_to_int, int_to_ip, debug_message, del_from_list, ip_in_network


class Router:
    def __init__(self, as_id, name=None):
        self.__interfaces = {}
        self.__bgp = {}
        self.__sockets = {}
        self.__th_main = None
        self.__routing_table_lock = threading.Lock()
        self.__routing_table = []
        self.__bgp_routing_table_lock = threading.Lock()
        self.__bgp_routing_table = []
        self.__propagated_bgp_networks = []

        self.__ping_lock = threading.Lock()
        self.__ping_received = False
        self.__ping_data = None

        self.name = name

        if not name:
            self.name = 'r' + str(as_id)

        self.as_id = as_id
        self.state = 0


    def __get_route(self, ip):
        if isinstance(ip, str):
            ip = ip_to_int(ip)
        found_route = None

        with self.__routing_table_lock:
            current_table = self.__routing_table

        for r in current_table:
            if ip_in_network(r.network, r.mask, ip):
                if not found_route:
                    found_route = r
                elif r.mask == found_route.mask:
                    if r.metric < found_route.metric:
                        found_route = r
                elif r.mask > found_route.mask:
                    found_route = r

        return found_route

    def __get_best_bgp_routes(self):
        store = {}
        with self.__bgp_routing_table_lock:
            for r in self.__bgp_routing_table:
                key = str(r.network) + "_" + str(r.mask)
                if key not in store:
                    store[key] = r
                else:
                    if len(r.path) < len(store[key].path):
                        store[key] = r

        return store

    def __add_route(self, r1):
        to_remove = None
        for key in range(len(self.__routing_table)):
            r2 = self.__routing_table[key]
            if r1.network == r2.network and r1.mask == r2.mask and r1.metric == r2.metric:
                if r2.source == 'B' and r1.source == 'B':
                    if len(r1.bgp_route.path) == len(r2.bgp_route.path) or len(r1.bgp_route.path) > len(
                            r2.bgp_route.path):
                        return False
                    else:
                        to_remove = key
                elif r1.gw == r2.gw:
                    return False
        if to_remove:
            with self.__routing_table_lock:
                self.__routing_table.pop(to_remove)

        with self.__routing_table_lock:
            self.__routing_table.append(r1)

        return True

    def __drop_route(self, bgp_route):
        with self.__routing_table_lock:
            for i in range(len(self.__routing_table)):
                r = self.__routing_table[i]
                if r.source == 'B':
                    if r.bgp_route and r.bgp_route == bgp_route:
                        self.__routing_table.pop(i)
                        return

    def __send_withdraw_route(self, bgp_route):
        for key, b in self.__bgp.items():
            if b.state != 'ESTABLISHED' or b.neighbour_as == bgp_route.source:
                continue

            b.withdraw_route(bgp_route)

    def __drop_bgp_routes(self, bgp_as):
        with self.__bgp_routing_table_lock:
            to_del = []
            for i in range(len(self.__bgp_routing_table)):
                r = self.__bgp_routing_table[i]

                if r.source == bgp_as:
                    to_del.append(i)
                    self.__drop_route(r)
                    self.__send_withdraw_route(r)

            del_from_list(self.__bgp_routing_table, to_del)

    def __main_thread(self):
        bgps_in_error_state = {}
        disabled_bgps = {}

        while self.state:
            best_bgp_routes = self.__get_best_bgp_routes()

            for key, bgp_route in best_bgp_routes.items():
                self.__add_route(Route(bgp_route.network, bgp_route.mask, bgp_route.next_hop, 'B', bgp_route=bgp_route))

            for key, b in self.__bgp.items():
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
                        debug_message(3, f"Router {self.name}", "main_thread",
                                      f"BGP is in error state. IP {b.my_ip}, AS {b.neighbour_as}.")
                        debug_message(3, f"Router {self.name}", "main_thread",
                                      f"Restarting BGP instance. IP {b.my_ip}, AS {b.neighbour_as}.")
                        b.off()
                        b.on()
                    else:
                        debug_message(3, f"Router {self.name}", "main_thread",
                                      f"BGP is in error state for a long time. IP {b.my_ip}, AS {b.neighbour_as}.")
                        disabled_bgps[b.my_ip] = b
                        self.__drop_bgp_routes(b.neighbour_as)
                        debug_message(3, f"Router {self.name}", "main_thread",
                                      f"Disabling BGP instance. IP {b.my_ip}, AS {b.neighbour_as}.")
                elif b.state == 'ESTABLISHED':
                    if b.my_ip in bgps_in_error_state:
                        bgps_in_error_state.pop(b.my_ip)

                    b.add_internal_routes(self.__propagated_bgp_networks)
                    b.add_shared_routes(best_bgp_routes.values())

            msg = ''
            if len(self.__routing_table):
                msg = f"Routing table: \n"
                msg += f"AS   Source  Network  Mask Gateway   Interface AS-PATH\n"
            for r in self.__routing_table:
                as_path = ''
                if r.bgp_route:
                    as_path = ' '.join(map(str, r.bgp_route.path))
                msg += f"{self.as_id}   {r.source}  {int_to_ip(r.network)}  {int_to_ip(r.mask)} {int_to_ip(r.gw)}   {int_to_ip(r.interface)}    {as_path} \n"
            if len(self.__routing_table):
                debug_message(3, f"Router {self.name}", "main_thread", msg)

            sleep(10)

    def __print_route(self, route):
        if route:
            print(f'Network: {int_to_ip(route.network)}, Mask: {int_to_ip(route.mask)}, Gw: {int_to_ip(route.gw)},Int: {int_to_ip(route.interface)}')

    def __clear_storage(self):
        self.__sockets = {}
        self.__routing_table = []
        self.__bgp_routing_table = []

    def add_bgp_network(self, network, mask):
        network = ip_to_int(network)
        mask = ip_to_int(mask)
        self.__propagated_bgp_networks.append((network, mask))

    def add_interface(self, i):
        i.install(self)
        self.__interfaces[i.ip] = i

    def get_port(self, src_ip, src_port, sock):
        if src_ip not in self.__interfaces:
            return False

        if src_ip in self.__sockets:
            if src_port in self.__sockets[src_ip]:
                return False
            else:
                self.__sockets[src_ip][src_port] = sock
                return True
        else:
            self.__sockets[src_ip] = {}
            self.__sockets[src_ip][src_port] = sock
            return True

    def release_port(self, src_ip, src_port, sock):
        if src_ip in self.__sockets:
            if src_port in self.__sockets[src_ip]:
                if self.__sockets[src_ip][src_port] == sock:
                    del self.__sockets[src_ip][src_port]

    def add_bgp_route(self, network, mask, next_hop, as_path, source):
        with self.__bgp_routing_table_lock:
            self.__bgp_routing_table.append(
                BGPRoute(network, mask, next_hop, ' '.join(map(str, as_path)), source=source))

    def set_bgp(self, b):
        if b.my_ip in self.__interfaces:
            b.install(self)
            self.__bgp[b.my_ip] = b

    def receive_data(self, i, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if dst_ip not in self.__interfaces:
                self.send_data(packet.getlayer(IP))
                debug_message(5, f"Router {self.name}", "receive_data",
                              f"Router got a packet to route, dst: {dst_ip}")
            else:
                if packet.haslayer(TCP):
                    dport = packet[TCP].dport
                    if dst_ip in self.__sockets:
                        if dport in self.__sockets[dst_ip]:
                            s = self.__sockets[dst_ip][dport]
                            s.receive_data(packet)
                else:
                    if packet.haslayer(ICMP):
                        icmp = packet.getlayer(ICMP)
                        # request
                        if icmp.type == 8:
                            answer = IP(src=packet[IP].dst, dst=packet[IP].src, ttl=20) / ICMP(type="echo-reply",
                                                                                               code=0)
                            self.send_data(answer)
                            debug_message(5, f"Router {self.name}", "receive_data",
                                          f"Router got ICMP request packet from {packet[IP].dst}, answering...")
                        # response
                        elif icmp.type == 0:
                            with self.__ping_lock:
                                if not self.__ping_received:
                                    self.__ping_received = True
                                    self.__ping_data = packet
        else:
            debug_message(5, f"Router {self.name}", "receive_data",
                          f"Router received a packet without IP header.")

    def on(self):
        if self.state != 0:
            return

        debug_message(5, f"Router {self.name}", "on", "Starting...")
        self.__clear_storage()

        self.state = 1

        for key, i in self.__interfaces.items():
            self.__routing_table.append(Route(i.ip, i.mask, '0.0.0.0', 'C', i.ip, 0))
            i.on()

        debug_message(5, f"Router {self.name}", "on", "Interfaces started.")

        self.__th_main = threading.Thread(target=self.__main_thread)
        self.__th_main.start()

        debug_message(5, f"Router {self.name}", "on", "Main thread started.")

        for key, b in self.__bgp.items():
            b.on()

        debug_message(5, f"Router {self.name}", "on", "BGP instances initialised.")

    def receive_withdraw_route(self, network, mask, as_id):
        debug_message(3, f"Router {self.name}", "receive_withdraw_route",
                      f"Withdraw message received: {int_to_ip(network)}, {int_to_ip(mask)}, source: {as_id}")
        with self.__bgp_routing_table_lock:
            to_del = []
            for i in range(len(self.__bgp_routing_table)):
                r = self.__bgp_routing_table[i]
                if r.network == network and r.mask == mask and r.source == as_id:
                    to_del.append(i)

            for i in to_del:
                r = self.__bgp_routing_table[i]
                self.__send_withdraw_route(r)
                self.__drop_route(r)

            del_from_list(self.__bgp_routing_table, to_del)

    def send_data(self, packet):
        route = self.__get_route(packet[IP].dst)
        #self.__print_route(route)
        if route:
            if route.interface != 0:
                self.__interfaces[int_to_ip(route.interface)].send_data(packet)
            else:
                route_to_gw = self.__get_route(route.gw)
                if route_to_gw.interface != 0:
                    self.__interfaces[int_to_ip(route_to_gw.interface)].send_data(packet, int_to_ip(route.gw))
                else:
                    debug_message(3, f"Router {self.name}", "send_data",
                                  f"No route to host {packet.gw}")
        else:
            debug_message(3, f"Router {self.name}", "send_data",
                          f"No route to host {packet.dst}")

    def off(self):
        if self.state == 0:
            return

        self.state = 0
        debug_message(5, f"Router {self.name}", "off", "Shutting down...")

        for key, b in self.__bgp.items():
            b.off()
        debug_message(5, f"Router {self.name}", "off", "BGP instances disabled.")

        for key, i in self.__interfaces.items():
            i.off()

        debug_message(5, f"Router {self.name}", "off", "Interfaces disabled.")

        self.__clear_storage()

        debug_message(5, f"Router {self.name}", "off", "Router shut down.")

    def get_interfaces(self):
        return self.__interfaces.keys()

    def ping(self, dst_ip, src_ip=None):
        if len(self.__interfaces) == 0:
            return 'No interfaces'

        if not src_ip or src_ip not in self.__interfaces:
            src_ip = list(self.__interfaces.keys())[0]
        msg = f'Ping sent from {src_ip} to {dst_ip} ... '

        with self.__ping_lock:
            self.__ping_received = False
            self.__ping_data = None
            packet = IP(src=src_ip, dst=dst_ip, ttl=20) / ICMP()
            self.send_data(packet)

        debug_message(5, f"Router {self.name}", "ping", f"Sending ping from {src_ip} to {dst_ip}")

        timeout = 10
        while timeout > 0 and not self.__ping_received:
            timeout -= 1
            sleep(1)

        with self.__ping_lock:
            if self.__ping_received:
                packet = self.__ping_data
                msg += f'answer received from {packet[IP].src}.'
                self.__ping_received = False
                self.__ping_data = None
            else:
                msg += 'no answer after 10 seconds'

        return msg



