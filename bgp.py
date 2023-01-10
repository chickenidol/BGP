from sock import Sock
from time import sleep
import threading
from random import randint
from scapy.contrib.bgp import BGPHeader, BGPOpen, BGPUpdate, BGPPathAttr, BGPNLRI_IPv4, BGPPALocalPref, BGPKeepAlive, \
    BGPPANextHop, BGPPAAS4BytesPath, BGPPAASPath

from tools import int_to_ip, netmask_to_bits, craft_bgp_update, ip_to_int, cidr_to_netmask, debug_message


class BGP:
    def __init__(self, my_as, neighbour_as, my_ip, neighbour_ip):
        self.__neighbour_keepalive = 0
        self.__th_main = None

        self.__working_socket = None
        self.__server_socket = None
        self.__client_socket = None

        self.__router = None

        self.__container = []
        self.__data_lock = threading.Lock()

        self.__shared_routes = {}

        self.my_as = my_as
        self.neighbour_as = neighbour_as
        self.my_ip = my_ip
        self.neighbour_ip = neighbour_ip
        # IDLE, CONNECT, ACTIVE, OPEN SENT, OPEN CONFIRM, ESTABLISHED, ERROR
        self.state = 'IDLE'
        self.error_code = 0
        self.hold_time = 30

    def __listen_thread(self, s):
        conn, addr = s.accept()
        self.__server_socket = conn

    def __receive_thread(self):
        while self.state == 'ESTABLISHED':
            if self.__working_socket and self.__working_socket.state == 'ESTABLISHED':
                data = self.__working_socket.recv()
                if data:
                    if data.haslayer(BGPKeepAlive):
                        self.__neighbour_keepalive = 0
                        debug_message(3, f"BGP AS {self.my_as}, IP {self.my_ip}, Neighbour {self.neighbour_as}",
                                      "receive_thread",
                                      f"Received KEEPALIVE from AS {self.neighbour_as} {self.neighbour_ip}.")
                    elif data.haslayer(BGPUpdate):
                        up_layer = data.getlayer(BGPUpdate)


                        if up_layer.withdrawn_routes:
                            for i in range(len(up_layer.withdrawn_routes)):
                                nlri = up_layer.withdrawn_routes[i].prefix
                                network = nlri.split('/')[0]
                                mask = cidr_to_netmask(nlri.split('/')[1])

                                self.__router.receive_withdraw_route(ip_to_int(network), ip_to_int(mask), self.neighbour_as)

                        if up_layer.path_attr and len(up_layer.path_attr):
                            debug_message(3, f"BGP AS {self.my_as}, IP {self.my_ip}, Neighbour {self.neighbour_as}",
                                          "receive_thread",
                                          f"Received UPDATE from AS {self.neighbour_as} {self.neighbour_ip}.")
                            nlri = up_layer.nlri[0].prefix
                            network = nlri.split('/')[0]
                            mask = cidr_to_netmask(nlri.split('/')[1])
                            as_path = []

                            if up_layer.haslayer(BGPPAAS4BytesPath):
                                segments = up_layer.getlayer(BGPPAAS4BytesPath).segments

                                for s in segments:
                                    as_path.append(s.segment_value[0])

                                h = up_layer.getlayer(BGPPANextHop)
                                next_hop = h.next_hop

                                self.__router.add_bgp_route(network, mask, next_hop, as_path, source=self.neighbour_as)
            sleep(0.1)

    def __handshake(self):
        server_socket = Sock(self.__router)
        server_socket.bind((self.my_ip, 179))
        if server_socket.listen():
            th_listen = threading.Thread(target=self.__listen_thread, args=(server_socket,))
            th_listen.start()

            sleep_time = randint(0, 12) * 10
            while not self.__server_socket and sleep_time != 0:
                sleep_time -= 1
                sleep(0.1)

            if self.__server_socket:
                return 0, self.__server_socket

        server_socket.close()

        client_socket = Sock(self.__router)
        client_socket.bind((self.my_ip, 0))

        if client_socket.connect((self.neighbour_ip, 179)):
            return 1, client_socket
        else:
            debug_message(3, f"BGP AS {self.my_as}, IP {self.my_ip}, Neighbour {self.neighbour_as}", "handshake",
                          f"TCP connection exceeded timeout. {self.my_ip}:random_free -> {self.neighbour_ip}:179")

            client_socket.close()
            return None, None

    def __main_thread(self):
        self.state = 'CONNECT'
        client = 0

        # establish TCP connection
        connect_tries = 0
        debug_message(4, f"BGP AS {self.my_as}, IP {self.my_ip}, Neighbour {self.neighbour_as}", "main_thread",
                      f"Initialising TCP connection.")
        while self.state != 'ACTIVE' and self.state != 'IDLE':
            shake = self.__handshake()
            if shake[1]:
                self.state = 'ACTIVE'
                client = shake[0]
                self.__working_socket = shake[1]
                debug_message(3, f"BGP AS {self.my_as}, IP {self.my_ip}, Neighbour {self.neighbour_as}", "main_thread",
                              f"TCP connection initialised. {self.__working_socket.src_ip}:{self.__working_socket.sport} -> {self.__working_socket.dst_ip}:{self.__working_socket.dport}")
                break

            connect_tries += 1
            if connect_tries > 3:
                self.state = 'ERROR'
                self.error_code = 5
                debug_message(2, f"BGP AS {self.my_as}, IP {self.my_ip}, Neighbour {self.neighbour_as}", "main_thread",
                              f"Error 5. Unable to establish TCP connection after {connect_tries} tries.")
                connect_tries = 0
                break
        # establish BGP connection
        if self.state == 'ACTIVE':
            debug_message(4, f"BGP AS {self.my_as}, IP {self.my_ip}, Neighbour {self.neighbour_as}", "main_thread",
                          f"Initialising BGP conversation.")
            hdr = BGPHeader(type=1, marker=0xffffffffffffffffffffffffffffffff)
            op = BGPOpen(my_as=self.my_as, hold_time=self.hold_time, bgp_id=self.my_ip)

            # we are the client, send BGP Open
            if client:
                bgp = hdr / op
                self.__working_socket.sendall(bgp)
                self.state = 'OPEN SENT'

            data = self.__working_socket.recv()

            if data and data.haslayer(BGPHeader) and data.haslayer(BGPOpen):
                rbgp = data.getlayer('OPEN')
                if self.neighbour_as == rbgp.my_as and self.neighbour_ip == rbgp.bgp_id:
                    if self.state == 'OPEN SENT':
                        if self.hold_time > rbgp.hold_time:
                            self.hold_time = rbgp.hold_time

                        self.state = 'OPEN CONFIRM'
                        sleep(0.1)
                        self.state = 'ESTABLISHED'

                    elif self.state == 'ACTIVE':
                        if self.hold_time > rbgp.hold_time:
                            self.hold_time = rbgp.hold_time

                        op = BGPOpen(my_as=self.my_as, hold_time=self.hold_time, bgp_id=self.my_ip)
                        bgp_answer = hdr / op
                        self.__working_socket.sendall(bgp_answer)
                        self.state = 'ESTABLISHED'
                else:
                    self.state = 'ERROR'
                    self.error_code = 2
                    debug_message(2, f"BGP AS {self.my_as}, IP {self.my_ip}, Neighbour {self.neighbour_as}",
                                  "main_thread",
                                  f"Error 2. Incorrect neighbour AS received.")
                    # send NOTIFICATION message
            else:
                self.state = 'ERROR'
                self.error_code = 1
                debug_message(2, f"BGP AS {self.my_as}, IP {self.my_ip}, Neighbour {self.neighbour_as}",
                              "main_thread",
                              f"Error 1. Error receiving data.")

        th_receive = None

        if self.state == 'ESTABLISHED':
            debug_message(3, f"BGP AS {self.my_as}, IP {self.my_ip}, Neighbour {self.neighbour_as}", "main_thread",
                          f"BGP conversation established.")
            # start recv threat
            th_receive = threading.Thread(target=self.__receive_thread)
            th_receive.start()

            keepalive_timer = self.hold_time / 3
            self.__neighbour_keepalive = 0

            while self.state == 'ESTABLISHED':
                if self.hold_time > 0:
                    if keepalive_timer == self.hold_time / 3:
                        kpa = BGPKeepAlive()
                        self.__working_socket.sendall(kpa)
                        keepalive_timer = 0

                    if self.__neighbour_keepalive > self.hold_time:
                        self.state = 'ERROR'
                        self.error_code = 4
                        debug_message(2, f"BGP AS {self.my_as}, IP {self.my_ip}, Neighbour {self.neighbour_as}",
                                      "main_thread",
                                      f"Error 4. No keepalive from the neighbour.")

                    keepalive_timer += 1
                    self.__neighbour_keepalive += 1

                with self.__data_lock:
                    while len(self.__container) > 0:
                        data = self.__container.pop(0)
                        self.__working_socket.sendall(data)

                sleep(1)
        else:
            self.state = 'ERROR'
            self.error_code = 3
            debug_message(2, f"BGP AS {self.my_as}, IP {self.my_ip}, Neighbour {self.neighbour_as}",
                          "main_thread",
                          f"Error 3. Unable to initialise BGP conversation.")

        if self.__working_socket:
            self.__working_socket.close()

        if th_receive:
            th_receive.join()

    def install(self, r):
        self.__router = r

    def add_internal_routes(self, routes):
        hdr = BGPHeader(type=2, marker=0xffffffffffffffffffffffffffffffff)

        for r in routes:
            network = int_to_ip(r[0])
            mask = str(netmask_to_bits(int_to_ip(r[1])))
            nlri = network + '/' + mask
            as_path = [self.my_as]
            key = nlri + "_" + ' '.join(map(str, as_path))

            if key not in self.__shared_routes:
                self.__shared_routes[key] = (nlri, as_path)
                bgp_update = hdr / craft_bgp_update('IGP', as_path, self.my_ip, nlri)
                with self.__data_lock:
                    self.__container.append(bgp_update)

    def withdraw_route(self, r):
        hdr = BGPHeader(type=2, marker=0xffffffffffffffffffffffffffffffff)

        network = int_to_ip(r.network)
        mask = netmask_to_bits(int_to_ip(r.mask))
        nlri = network + '/' + str(mask)
        as_path = [self.my_as] + r.path
        key = nlri + "_" + ' '.join(map(str, as_path))
        if key in self.__shared_routes:
            # self.1shared_routes[key] = (nlri, as_path)
            bgp_update = hdr / BGPUpdate(withdrawn_routes_len=None, withdrawn_routes=[BGPNLRI_IPv4(prefix=nlri)])
            with self.__data_lock:
                self.__container.append(bgp_update)

    def add_shared_routes(self, routes):
        hdr = BGPHeader(type=2, marker=0xffffffffffffffffffffffffffffffff)

        for r in routes:
            n = int_to_ip(r.network)
            m = int_to_ip(r.mask)
            if self.my_as in r.path:
                continue

            if self.neighbour_as in r.path:
                continue

            network = int_to_ip(r.network)
            mask = netmask_to_bits(int_to_ip(r.mask))
            nlri = network + '/' + str(mask)
            as_path = [self.my_as] + r.path
            key = nlri + "_" + ' '.join(map(str, as_path))
            if key not in self.__shared_routes:
                self.__shared_routes[key] = (nlri, as_path)
                bgp_update = hdr / craft_bgp_update('IGP', as_path, self.my_ip, nlri)
                with self.__data_lock:
                    self.__container.append(bgp_update)

    def on(self):
        debug_message(5, f"BGP AS {self.my_as}, IP {self.my_ip}, Neighbour {self.neighbour_as}",
                      "on",
                      f"Starting...")
        self.__th_main = threading.Thread(target=self.__main_thread)
        self.__th_main.start()
        debug_message(5, f"BGP AS {self.my_as}, IP {self.my_ip}, Neighbour {self.neighbour_as}",
                      "on",
                      f"BGP instance started.")

    def off(self):
        debug_message(5, f"BGP AS {self.my_as}, IP {self.my_ip}, Neighbour {self.neighbour_as}",
                      "off",
                      f"Shutting down...")

        self.state = 'IDLE'
        sleep(1)
        self.state = 'IDLE'

        self.__th_main.join()

        debug_message(5, f"BGP AS {self.my_as}, IP {self.my_ip}, Neighbour {self.neighbour_as}",
                      "off",
                      f"Shut down.")

        self.__working_socket = None
        self.__client_socket = None
        self.__server_socket = None
        self.__shared_routes = {}

