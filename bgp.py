from sock import Sock
from time import sleep
import threading
from random import randint
from scapy.contrib.bgp import BGPHeader, BGPOpen, BGPUpdate, BGPPathAttr, BGPNLRI_IPv4, BGPPALocalPref, BGPKeepAlive, \
    BGPPANextHop, BGPPAAS4BytesPath, BGPPAASPath

from tools import int_to_ip, netmask_to_bits, craft_bgp_update, ip_to_int, cidr_to_netmask


class BGP:
    def __init__(self, my_as, neighbour_as, my_ip, neighbour_ip):
        self.my_as = my_as
        self.neighbour_as = neighbour_as
        self.neighbour_keepalive = 0
        self.my_ip = my_ip
        self.neighbour_ip = neighbour_ip
        # IDLE, CONNECT, ACTIVE, OPEN SENT, OPEN CONFIRM, ESTABLISHED, ERROR
        self.state = 'IDLE'
        self.error_code = 0
        self.thmain = None

        self.working_socket = None
        self.server_socket = None
        self.client_socket = None

        self.router = None
        self.hold_time = 90

        self.container = []
        self.data_lock = threading.Lock()

        self.shared_routes = {}

    def install(self, r):
        self.router = r

    def listen_thread(self, s):
        conn, addr = s.accept()
        self.server_socket = conn

    def receive_thread(self):
        while self.state == 'ESTABLISHED':
            if self.working_socket and self.working_socket.state == 'ESTABLISHED':
                data = self.working_socket.recv()
                if data:
                    if data.haslayer(BGPKeepAlive):
                        self.neighbour_keepalive = 0
                        print(f"{self.my_ip} received KEEPALIVE")
                    elif data.haslayer(BGPUpdate):
                        up_layer = data.getlayer(BGPUpdate)
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

                            self.router.add_bgp_route(network, mask, next_hop, as_path)

                    # встречаем UPDATE, обрабатываем, дергаем callback роутера, передаем массив маршрутов
                    # он который вносит данные в список BGP с блокировкой

            sleep(0.1)

    def handshake(self):
        server_socket = Sock(self.router)
        server_socket.bind((self.my_ip, 179))
        if server_socket.listen():
            th_listen = threading.Thread(target=self.listen_thread, args=(server_socket,))
            th_listen.start()

            sleep_time = randint(0, 12) * 10
            while not self.server_socket and sleep_time != 0:
                sleep_time -= 1
                sleep(0.1)

            if self.server_socket:
                return 0, self.server_socket

        server_socket.close()

        client_socket = Sock(self.router)
        client_socket.bind((self.my_ip, 0))

        if client_socket.connect((self.neighbour_ip, 179)):
            return 1, client_socket
        else:
            client_socket.close()
            return None, None

    def add_internal_routes(self, routes):
        hdr = BGPHeader(type=2, marker=0xffffffffffffffffffffffffffffffff)

        for r in routes:
            network = int_to_ip(r[0])
            mask = str(netmask_to_bits(int_to_ip(r[1])))
            nlri = network + '/' + mask
            as_path = [self.my_as]
            key = nlri + "_" + ' '.join(map(str, as_path))
            if key not in self.shared_routes:
                self.shared_routes[key] = (nlri, as_path)
                bgp_update = hdr / craft_bgp_update('IGP', as_path, self.my_ip, nlri)
                with self.data_lock:
                    self.container.append(bgp_update)

    def add_shared_routes(self, routes):
        hdr = BGPHeader(type=2, marker=0xffffffffffffffffffffffffffffffff)

        for r in routes:
            if self.my_as in r.path:
                continue

            if self.neighbour_as in r.path:
                continue

            network = int_to_ip(r.network)
            mask = netmask_to_bits(int_to_ip(r.mask))
            nlri = network + '/' + mask
            as_path = [self.my_as] + r.path
            key = nlri + "_" + ' '.join(as_path)
            if key not in self.shared_routes:
                self.shared_routes[key] = (nlri, as_path)
                bgp_update = hdr / craft_bgp_update('IGP', as_path, self.my_ip, nlri)
                with self.data_lock:
                    self.container.append(bgp_update)

    def main_thread(self):
        self.state = 'CONNECT'
        client = 0

        # establish TCP connection
        while self.state != 'ACTIVE' and self.state != 'IDLE':
            shake = self.handshake()
            if shake[1]:
                self.state = 'ACTIVE'
                client = shake[0]
                self.working_socket = shake[1]
                break
        # establish BGP connection
        if self.state == 'ACTIVE':
            hdr = BGPHeader(type=1, marker=0xffffffffffffffffffffffffffffffff)
            op = BGPOpen(my_as=self.my_as, hold_time=self.hold_time, bgp_id=self.my_ip)

            # we are the client, send BGP Open
            if client:
                bgp = hdr / op
                self.working_socket.sendall(bgp)
                self.state = 'OPEN SENT'

            data = self.working_socket.recv()

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
                        self.working_socket.sendall(bgp_answer)
                        self.state = 'ESTABLISHED'
                else:
                    self.state = 'ERROR'
                    self.error_code = 2
                    print(f"2. {self.my_ip} Wrong neighbour.")
                    # send NOTIFICATION message
            else:
                self.state = 'ERROR'
                self.error_code = 1
                print(f"1. {self.my_ip} Error receiving data.")

        th_receive = None

        if self.state == 'ESTABLISHED':
            # start recv threat
            th_receive = threading.Thread(target=self.receive_thread)
            th_receive.start()

            keepalive_timer = self.hold_time / 3
            self.neighbour_keepalive = 0

            while self.state == 'ESTABLISHED':
                if self.hold_time > 0:
                    if keepalive_timer == self.hold_time / 3:
                        kpa = BGPKeepAlive()
                        self.working_socket.sendall(kpa)
                        keepalive_timer = 0

                    if self.neighbour_keepalive > self.hold_time:
                        self.state = 'ERROR'
                        self.error_code = 4
                        print(f'4. No keepalive from the neighbour. {self.my_ip}')

                    keepalive_timer += 1
                    self.neighbour_keepalive += 1

                with self.data_lock:
                    while len(self.container) > 0 and self.state != 'IDLE':
                        data = self.container.pop(0)
                        self.working_socket.sendall(data)

                sleep(1)
        else:
            self.state = 'ERROR'
            self.error_code = 3
            print(f'3. {self.my_ip} Error initialising BGP conversation.')

        if self.working_socket:
            self.working_socket.close()

        if th_receive:
            th_receive.join()

    def on(self):
        self.thmain = threading.Thread(target=self.main_thread)
        self.thmain.start()

    def off(self):
        self.state = 'IDLE'
        self.thmain.join()
        self.working_socket = None
        self.client_socket = None
        self.server_socket = None

