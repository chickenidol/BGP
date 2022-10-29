import threading
from time import sleep
from random import randint
from scapy.all import *
import scapy.all as scapy
from scapy.layers.inet import IP, ICMP, Ether, TCP
from scapy.contrib.bgp import BGPHeader, BGPOpen, BGPUpdate, BGPPathAttr, BGPNLRI_IPv4, BGPPALocalPref, BGPKeepAlive


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
                "state": "IDLE",
                "hold_time": 90,
                "neighbour_as": None,
                "neighbour_id": None,
                "keepalive_timer": 0
            }
        }

        self.sessions[i.ip] = {}

    def set_bgp(self, ip, status, neighbour_as=None, neighbour_id=None, hold_time = 90):
        self.interfaces[ip]['bgp']['status'] = status
        self.interfaces[ip]['bgp']['hold_time'] = hold_time
        self.interfaces[ip]['bgp']['neighbour_as'] = neighbour_as
        self.interfaces[ip]['bgp']['neighbour_id'] = neighbour_id
        self.interfaces[ip]['bgp']['keepalive_timer'] = 0

    def bgp_executor(self, session, data):
        # получили что то по bgp
        # если пришел OPEN запрос - поменяли статус, ответили
        # KEEPALIVE - ответ сразу
        # UPDATE - обработали данные, обновили ack
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

        session = {
            'sport': src_port,
            'dport': dst_port,
            'seq_num': seq_num,
            'ack_num': ack_num,
            'direction': direction,
            'state': state  # LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, CLOSING, CLOSED
        }

        key = len(self.sessions[interface_ip][neighbour_ip]['tcp'])

        self.sessions[interface_ip][neighbour_ip]['tcp'].append({
            'sport': src_port,
            'dport': dst_port,
            'seq_num': seq_num,
            'ack_num': ack_num,
            'direction': direction,
            'state': state  # LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, CLOSING, CLOSED
        })

        return self.sessions[interface_ip][neighbour_ip]['tcp'][key]

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
                    self.interfaces[interface.ip]['bgp']['state'] = 'CONNECT'
                    # choose ack_seq
                    seq_num = randint(1, 2 ** 30)
                    new_session = self.create_session(dst_ip, src_ip, packet[TCP].sport, packet[TCP].dport, 'SYN-RECEIVED', 'IN',
                                        seq_num, packet[TCP].seq + 1)

                    packet_syn_ack = self.craft_tcp(interface.ip, src_ip, new_session, 'SA')
                    interface.send_data(packet_syn_ack)
                    new_session['seq_num'] += 1
            elif packet[TCP].flags == 'SA':
                session = self.get_session_by_port(dst_ip, src_ip, packet[TCP].dport, packet[TCP].sport, 'OUT')

                if session and session['state'] == 'SYN-SENT':
                    session['ack_num'] = packet[TCP].seq + 1
                    packet_ack = self.craft_tcp(interface.ip, src_ip, session, 'A')
                    interface.send_data(packet_ack)
                    session['state'] = 'ESTABLISHED'
                    sleep(1)
                    self.interfaces[interface.ip]['bgp']['state'] = 'ACTIVE'
            elif packet[TCP].flags == 'A':
                session = self.get_session_by_port(dst_ip, src_ip, packet[TCP].sport, packet[TCP].dport, 'IN')
                if session['state'] == 'SYN-RECEIVED':
                    session['state'] = 'ESTABLISHED'
                    self.interfaces[interface.ip]['bgp']['state'] = 'ACTIVE'
                    session['ack_num'] = packet[TCP].seq
            elif packet[TCP].flags == 'R':
                session = self.get_session_by_port(dst_ip, src_ip, packet[TCP].dport, packet[TCP].sport)

                if session and session['state'] == 'SYN-SENT':
                    # mark session as 'CLOSING'
                    session['state'] = 'CLOSING'
                    # add random number as timeout, timeout-- in main cycle later drop when 0
                    session['closing_counter'] = randint(1, 15)
            else:
                bgp_session = self.interfaces[interface.ip]['bgp']
                if packet.haslayer(BGPHeader):
                    # we got OPEN
                    if bgp_session['state'] == 'ACTIVE' and packet.haslayer(BGPOpen):
                        bgp = packet.getlayer('OPEN')
                        session = self.get_session_by_port(dst_ip, src_ip, packet[TCP].sport, packet[TCP].dport)
                        if bgp_session['neighbour_as'] == bgp.my_as and bgp_session['neighbour_id'] == bgp.bgp_id:
                            session['ack_num'] += len(packet[TCP].payload)
                            open_packet = self.craft_tcp(interface.ip, bgp.bgp_id, session)
                            hdr = BGPHeader(type=1, marker=0xffffffffffffffffffffffffffffffff)

                            if bgp_session['hold_time'] > bgp.hold_time:
                                bgp_session['hold_time'] = bgp.hold_time

                            op = BGPOpen(my_as=self.as_id, hold_time=bgp_session['hold_time'], bgp_id=interface.ip)
                            full_packet = open_packet / hdr / op
                            session['seq_num'] += len(full_packet[TCP].payload)
                            interface.send_data(full_packet)
                            bgp_session['state'] = 'ESTABLISHED'
                    # we sent OPEN and got an answer
                    elif bgp_session['state'] == 'OPEN SENT' and packet.haslayer(BGPOpen):
                        bgp = packet.getlayer('OPEN')
                        session = self.get_session_by_port(dst_ip, src_ip, packet[TCP].dport, packet[TCP].sport)
                        bgp_session['state'] = 'ESTABLISHED'

                        if bgp_session['hold_time'] > bgp.hold_time:
                            bgp_session['hold_time'] = bgp.hold_time

                        bgp_session['keepalive_timer'] = 0
                        session['ack_num'] += len(packet[TCP].payload)
                        packet_ack = self.craft_tcp(interface.ip, src_ip, session, 'A')
                        interface.send_data(packet_ack)
                    # got KEEPALIVE
                elif packet.haslayer(BGPKeepAlive) and bgp_session['state'] == 'ESTABLISHED':
                    print("GOT KEEPALIVE")

    def craft_tcp(self, src_ip, dst_ip, session, flags=''):
        sport = session['sport']
        dport = session['dport']

        if session['direction'] == 'IN':
            sport = session['dport']
            dport = session['sport']

        packet = IP(src=src_ip, dst=dst_ip, ttl=20) / TCP(
            sport=sport,
            dport=dport,
            flags=flags,
            seq=session['seq_num'],
            ack=session['ack_num'])
        return packet

    
    def automate(self):
        for key, i in self.interfaces.items():
            with self.sessions_lock:
                bgp_session = i['bgp']
                if bgp_session['status'] == 'On':
                    #print(i['bgp']['state'])
                    session = self.get_any_session_by_port(i['ip'], bgp_session['neighbour_id'], 179)
                    if session is None:
                        i['bgp']['state'] = 'CONNECT'
                        seq_num = randint(1, 2 ** 30)
                        src_port = randint(49152, 65535)
                        new_session = self.create_session(i['ip'], bgp_session['neighbour_id'], src_port, 179, 'SYN-SENT', 'OUT', seq_num)
                        packet_syn = self.craft_tcp(i['ip'], bgp_session['neighbour_id'], new_session, 'S')
                        new_session['seq_num'] += 1
                        i['obj'].send_data(packet_syn)
                    elif session['state'] == 'CLOSING':
                        session['closing_counter'] = session['closing_counter'] - 1

                        if session['closing_counter'] == 0:
                            to_del = None
                            for j in range(len(self.sessions[i['ip']][bgp_session['neighbour_id']]['tcp'])):
                                if self.sessions[i['ip']][bgp_session['neighbour_id']]['tcp'][j] == session:
                                    to_del = j

                            self.sessions[i['ip']][bgp_session['neighbour_id']]['tcp'].pop(to_del)
                    else:
                        # send OPEN
                        if bgp_session['state'] == 'ACTIVE' and session['direction'] == 'OUT':
                            packet = self.craft_tcp(i['ip'], bgp_session['neighbour_id'], session)
                            hdr = BGPHeader(type=1,
                                            marker=0xffffffffffffffffffffffffffffffff)
                            op = BGPOpen(my_as=self.as_id, hold_time=bgp_session['hold_time'], bgp_id=i['ip'])

                            bgp = packet / hdr / op
                            i['obj'].send_data(bgp)
                            bgp_session['state'] = 'OPEN SENT'
                            session['seq_num'] = session['seq_num'] + len(bgp[TCP].payload)
                        elif bgp_session['state'] == 'ESTABLISHED':
                            if bgp_session['keepalive_timer'] == 0:
                                #send KEEPALIVE
                                bgp_kpa = self.craft_tcp(i['ip'], bgp_session['neighbour_id'], session)
                                hdr = BGPHeader(type=4, marker=0xffffffffffffffffffffffffffffffff)
                                kpa = BGPKeepAlive()
                                full_packet = bgp_kpa / hdr / kpa
                                session['seq_num'] += len(full_packet[TCP].payload)
                                i['obj'].send_data(full_packet)

                                bgp_session['keepalive_timer'] = bgp_session['hold_time'] * 2
                            else:
                                bgp_session['keepalive_timer'] -= 1

        sleep(0.5)

    def on(self):
        self.state = 1

        for key, value in self.interfaces.items():
            i_thread = value['obj'].on()
            self.interfaces[key]['thread'] = i_thread
            i_thread.start()

        thread = threading.Thread(target=self.main_thread)
        thread.start()
        return thread

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
