import threading
from time import sleep
from random import randint
from scapy.all import *
import scapy.all as scapy
from scapy.layers.inet import IP, ICMP, Ether, TCP
from scapy.layers.l2 import ARP

class Router:
    def __init__(self, name, as_id=None):
        self.name = name
        self.as_id = as_id
        self.interfaces = {}
        self.state = 0
        self.bgp_session = {}
        self.sessions = {}
        self.sessions_lock = threading.Lock()

    def add_interface(self, i):
        i.install(self)

        self.interfaces[i.ip] = {
            "ip": i.ip,
            "thread": None,
            "obj": i,
            "bgp": {
                "status": "Off",
                "neighbour_as": None,
                "neighbour_id": None
            }
        }

        self.sessions[i.ip] = {}

    def set_bgp(self, ip, status, neighbour_as=None, neighbour_id=None):
        self.interfaces[ip]["bgp"] = {
            "status": status,
            "neighbour_as": neighbour_as,
            "neighbour_id": neighbour_id
        }

    def bgp_executor(self, session, data):
        print(data)

    # callback
    def receive_data(self, i, data):
        if data.haslayer(IP):
            # IP packet
            if data[IP].dst == i.ip:
                if data.haslayer(TCP):
                    if data[TCP].sport == 179 or data[TCP].dport == 179:
                        if self.interfaces[i.ip]['bgp']['neighbour_id'] == data[IP].src:
                            self.process_bgp(i, data)
            else:
                print("got routing packet")

    def get_any_session_by_port(self, interface_ip, dst_ip, port):
        session = None
        if interface_ip in self.sessions:
            if dst_ip in self.sessions[interface_ip]:
                if 'tcp' in self.sessions[interface_ip][dst_ip]:
                    for item in self.sessions[interface_ip][dst_ip]['tcp']:
                        if item['sport'] == port or item['dport'] == port:
                                session = item

        return session

    def get_session_by_port(self, interface_ip, dst_ip, sport, dport, direction=None):
        session = None
        if interface_ip in self.sessions:
            if dst_ip in self.sessions[interface_ip]:
                if 'tcp' in self.sessions[interface_ip][dst_ip]:
                    for item in self.sessions[interface_ip][dst_ip]['tcp']:
                        if item['sport'] == sport or item['dport'] == dport:
                            if direction:
                                if item['direction'] == direction:
                                    session = item
                            else:
                                session = item

        return session

    def create_session(self, interface_ip, neighbour_ip, src_port, dst_port, state, direction, seq_num=None, ack_num=0):
        if not seq_num:
            seq = randint(1, 2 ^ 30)

        if interface_ip not in self.sessions:
            self.sessions[interface_ip] = {}

        if neighbour_ip not in self.sessions[interface_ip]:
            self.sessions[interface_ip][neighbour_ip] = {}

        if 'tcp' not in self.sessions[interface_ip][neighbour_ip]:
            self.sessions[interface_ip][neighbour_ip]['tcp'] = []

        self.sessions[interface_ip][neighbour_ip]['tcp'].append({
            'sport': src_port,
            'dport': dst_port,
            'seq_num': seq_num,
            'ack_num': ack_num,
            'direction': direction,
            'state': state  # LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, CLOSING, CLOSED
        })

    def process_bgp(self, interface, packet):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        with self.sessions_lock:
            if packet[TCP].flags == 'S':
                session = self.get_any_session_by_port(dst_ip, src_ip, 179)

                if session and session['state'] != 'CLOSING':
                    packet_rst = IP(src=dst_ip, dst=src_ip, ttl=20) / TCP(sport=packet[TCP].dport,
                                                                                                 dport=packet[TCP].sport,
                                                                                                 flags='R',
                                                                                                 ack=packet[TCP].seq + 1)

                    interface.send_data(packet_rst)
                else:
                    # choose ack_seq
                    seq_num = randint(1, 2 ** 30)
                    self.create_session(dst_ip, src_ip, packet[TCP].sport, packet[TCP].dport, 'SYN-RECEIVED', 'IN',
                                        seq_num, packet[TCP].seq + 1)

                    packet_syn_ack = IP(src=dst_ip, dst=src_ip, ttl=20) / TCP(
                        sport=packet[TCP].dport,
                        dport=packet[TCP].sport, flags='SA',
                        seq=seq_num,
                        ack=packet[TCP].seq + 1)

                    interface.send_data(packet_syn_ack)
            elif packet[TCP].flags == 'SA':
                session = self.get_session_by_port(dst_ip, src_ip, packet[TCP].dport, packet[TCP].sport, 'OUT')

                if session and session['state'] == 'SYN-SENT':
                    session['ack_num'] = packet[TCP].seq + 1
                    session['seq_num'] = packet[TCP].ack

                    packet_ack = IP(src=dst_ip, dst=src_ip, ttl=20) / TCP(
                        sport=session['sport'],
                        dport=session['dport'], flags='A',
                        seq=session['seq_num'],
                        ack=session['ack_num'])

                    interface.send_data(packet_ack)
                    session['state'] = 'ESTABLISHED'
            elif packet[TCP].flags == 'A':
                session = self.get_session_by_port(dst_ip, src_ip, packet[TCP].sport, packet[TCP].dport, 'IN')
                if session['state'] == 'SYN-RECEIVED':
                    session['ack_num'] = packet[TCP].seq
            elif packet[TCP].flags == 'R':
                session = self.get_session_by_port(dst_ip, src_ip, packet[TCP].dport, packet[TCP].sport)

                if session and session['state'] == 'SYN-SENT':
                    # mark session as 'CLOSING'
                    session['state'] = 'CLOSING'
                    # add random number as timeout, timeout-- in main cycle later drop when 0
                    session['closing_counter'] = randint(1, 15)
            else:
                session = self.get_session_by_port(dst_ip, src_ip, packet[TCP].sport, packet[TCP].dport)
                self.bgp_executor(session, packet)

    def automate(self):
        for key, i in self.interfaces.items():
            with self.sessions_lock:
                if i['bgp']['status'] == 'On':
                    session = self.get_any_session_by_port(i['ip'], i['bgp']['neighbour_id'], 179)
                    if session is None:
                        seq_num = randint(1, 2 ** 30)
                        src_port = randint(49152, 65535)
                        self.create_session(i['ip'], i['bgp']['neighbour_id'], src_port, 179, 'SYN-SENT', 'OUT', seq_num)
                        packet_syn = IP(src=i['ip'], dst=i['bgp']['neighbour_id'], ttl=20) / TCP(sport=src_port, dport=179,
                                                                                                 flags='S', seq=seq_num)
                        i['obj'].send_data(packet_syn)
                    elif session['state'] == 'CLOSING':
                        session['closing_counter'] = session['closing_counter'] - 1

                        if session['closing_counter'] == 0:
                            to_del = None
                            for j in range(len(self.sessions[i['ip']][i['bgp']['neighbour_id']]['tcp'])):
                                if self.sessions[i['ip']][i['bgp']['neighbour_id']]['tcp'][j] == session:
                                    to_del = j

                            self.sessions[i['ip']][i['bgp']['neighbour_id']]['tcp'].pop(to_del)

    def on(self):
        self.state = 1

        for key, value in self.interfaces.items():
            i_thread = value['obj'].on()
            self.interfaces[key]['thread'] = i_thread
            i_thread.start()

        return threading.Thread(target=self.main_thread)

    def main_thread(self):
        while self.state:
            self.automate()
            sleep(0.1)

    def off(self):
        self.state = 0

        for i in self.interfaces:
            self.interfaces[i]["obj"].off()

        for i in self.interfaces:
            self.interfaces[i]["thread"].join()
