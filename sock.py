from scapy.layers.inet import IP, ICMP, Ether, TCP
from time import sleep
from random import randint
import threading

from tools import debug_message, craft_tcp


class Sock:
    def __init__(self, router):
        self.sport = 0
        self.dport = 0

        self.src_ip = 0
        self.dst_ip = 0

        self.seq_num = 0
        self.ack_num = 0
        # LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, CLOSING, CLOSED
        self.state = 'IDLE'

        self.__router = router

        self.__container = []
        self.__data_lock = threading.Lock()

        self.__port_acquired = False

    # params ((src_host, src_port))
    def bind(self, params):
        self.src_ip = params[0]
        self.sport = params[1]

        if self.sport == 0:
            self.sport = randint(49152, 65535)

    # read data
    def recv(self, size = 0):
        data = None

        while self.state != 'IDLE':
            with self.__data_lock:
                if len(self.__container) > 0:
                    data = self.__container.pop(0)
                    break
        return data

    # send data
    def sendall(self, data):
        packet = craft_tcp(self.src_ip, self.dst_ip, self.sport, self.dport, self.seq_num, self.ack_num, '')
        packet = packet / data
        self.__router.send_data(packet)
        self.seq_num += len(packet[TCP].payload)

    # listen before syn comes
    def listen(self):
        if self.state != 'IDLE':
            return False

        b_port = self.__router.get_port(self.src_ip, self.sport, self)
        if b_port:
            self.state = 'LISTEN'
            self.__port_acquired = True

        return b_port

    def accept(self):
        if self.state != 'LISTEN':
            return False

        while self.state != 'ESTABLISHED' and self.state != 'IDLE':
            sleep(0.1)

        if self.state == 'ESTABLISHED':
            return self, (self.dst_ip, self.dport)

        return None, None

    def connect(self, dst, timeout=5):
        if self.state != 'IDLE':
            return False

        if timeout < 1 or timeout > 120:
            timeout = 5

        self.dst_ip = dst[0]
        self.dport = dst[1]

        if self.__router.get_port(self.src_ip, self.sport, self):
            self.__port_acquired = True
            self.seq_num = randint(1, (2 ^ 32) - 1)

            packet_syn = craft_tcp(self.src_ip, self.dst_ip, self.sport, self.dport, self.seq_num, 0, 'S')
            self.__router.send_data(packet_syn)
            self.seq_num += 1
            self.state = 'SYN-SENT'

            while timeout > 0:
                timeout -= 1
                if self.state == 'ESTABLISHED':
                    return True

                sleep(1)

            self.close()

        return False

    def close(self):
        # send rst to a neighbour if there is one
        if self.state == 'SYN-RECEIVED' or self.state == 'ESTABLISHED':
            packet_rst = craft_tcp(self.src_ip, self.dst_ip, self.sport, self.dport, self.seq_num, 0, 'R')
            self.__router.send_data(packet_rst)

        self.state = 'IDLE'

        if self.__port_acquired:
            self.__router.release_port(self.src_ip, self.sport, self)

    # callback
    def receive_data(self, packet):
        if self.state == 'IDLE' or self.state == 'CLOSING' or self.state == 'CLOSED':
            return False

        if self.state == 'ESTABLISHED':
            # check if there is RST flag
            if packet[TCP].flags == 'R':
                self.close()
            # if no flag then put data to input queue
            else:
                # check ack and seq
                if packet[IP].src == self.dst_ip and \
                        packet[TCP].sport == self.dport:
                        #and packet[TCP].ack == self.seq_num:
                    with self.__data_lock:
                        self.__container.append(packet[TCP].payload)
                        # change ack
                        self.ack_num += len(packet[TCP].payload)

        if self.state == 'LISTEN':
            if packet[TCP].flags == 'S':
                self.seq_num = randint(1, 2 ** 29)

                self.dst_ip = packet[IP].src
                self.dport = packet[TCP].sport
                self.ack_num = packet[TCP].seq + 1
                packet_syn_ack = craft_tcp(self.src_ip, self.dst_ip, self.sport, self.dport, self.seq_num, self.ack_num, 'SA')
                self.__router.send_data(packet_syn_ack)
                self.seq_num += 1
                self.state = 'SYN-RECEIVED'
        elif self.state == 'SYN-RECEIVED':
            if packet[TCP].flags == 'A':
                if packet[IP].src == self.dst_ip and \
                        packet[TCP].sport == self.dport and \
                        packet[TCP].ack == self.seq_num:
                    self.state = 'ESTABLISHED'
        elif self.state == 'SYN-SENT':
            if packet[TCP].flags == 'SA':
                if packet[IP].src == self.dst_ip and \
                        packet[TCP].sport == self.dport and \
                        packet[TCP].ack == self.seq_num:
                    self.ack_num = packet[TCP].seq + 1
                    packet_ack = craft_tcp(self.src_ip, self.dst_ip, self.sport, self.dport, self.seq_num,
                                                self.ack_num, 'A')
                    self.__router.send_data(packet_ack)
                    self.state = 'ESTABLISHED'
                else:
                    packet_rst = craft_tcp(self.src_ip, self.dst_ip, self.sport, self.dport, self.seq_num, 0, 'R')
                    self.__router.send_data(packet_rst)
