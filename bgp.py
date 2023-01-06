from sock import Sock
from time import sleep
import threading
from random import randint
from scapy.contrib.bgp import BGPHeader, BGPOpen, BGPUpdate, BGPPathAttr, BGPNLRI_IPv4, BGPPALocalPref, BGPKeepAlive

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

    def update_route(self, route):
        with self.data_lock:
            # просто произвольный текст пока
            self.container.append(route)

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
            else:
                self.state = 'ERROR'
                self.error_code = 1
                print(f"1. {self.my_ip} Error receiving data.")

        th_receive = None

        if self.state == 'ESTABLISHED':
            # start recv threat
            th_receive = threading.Thread(target=self.receive_thread)
            th_receive.start()

            keepalive_timer = self.hold_time
            self.neighbour_keepalive = 0

            while self.state == 'ESTABLISHED':
                if self.hold_time > 0:
                    if keepalive_timer == self.hold_time:
                        kpa = BGPKeepAlive()
                        self.working_socket.sendall(kpa)
                        keepalive_timer = 0

                    if self.neighbour_keepalive > self.hold_time * 2:
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

