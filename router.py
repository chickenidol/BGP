import threading
from time import sleep
from random import randint
from scapy.all import *
import scapy.all as scapy
from scapy.layers.inet import IP, ICMP, Ether, TCP
from scapy.contrib.bgp import BGPHeader, BGPOpen, BGPUpdate, BGPPathAttr, BGPNLRI_IPv4, BGPPALocalPref


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
            "state": "IDLE",
            "status": status,
            "hold_time": 90,
            "neighbour_as": neighbour_as,
            "neighbour_id": neighbour_id
        }

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
                if packet.haslayer(BGPOpen):
                    bgp_settings = self.interfaces[interface.ip]['bgp']
                    bgp = packet.getlayer('OPEN')

                    if self.interfaces[interface.ip]['bgp']['state'] == 'ACTIVE':
                        session = self.get_session_by_port(dst_ip, src_ip, packet[TCP].sport, packet[TCP].dport)
                        if bgp_settings['neighbour_as'] == bgp.my_as and bgp_settings['neighbour_id'] == bgp.bgp_id:
                            bgp_settings['hold_time'] = bgp.hold_time
                            session['ack_num'] += len(packet[TCP].payload)

                            open_packet = self.craft_tcp(interface.ip, bgp.bgp_id, session)
                            hdr = BGPHeader(type=1, marker=0xffffffffffffffffffffffffffffffff)

                            op = BGPOpen(my_as=self.as_id, hold_time=90, bgp_id=interface.ip)

                            full_packet = open_packet / hdr / op
                            session['seq_num'] += len(full_packet[TCP].payload)
                            interface.send_data(full_packet)
                            self.interfaces[interface.ip]['bgp']['state'] = 'ESTABLISHED'
                    elif self.interfaces[interface.ip]['bgp']['state'] == 'OPEN SENT':
                        session = self.get_session_by_port(dst_ip, src_ip, packet[TCP].dport, packet[TCP].sport)
                        self.interfaces[interface.ip]['bgp']['state'] = 'ESTABLISHED'
                        session['ack_num'] += len(packet[TCP].payload)
                        packet_ack = self.craft_tcp(interface.ip, src_ip, session, 'A')
                        interface.send_data(packet_ack)


            # ANSWER

                # получили пакет
                # проверили последовательность
                    # если больше - то в кеш
                    # равно - вызываем bgp_executor
                    # проверяем есть ли что в кеше, если есть вызываем bgp_executor, выкидываем из кеша


    def craft_tcp(self, src_ip, dst_ip, session, flags = ''):
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
                #print(i['bgp']['state'])
                if i['bgp']['status'] == 'On':
                    session = self.get_any_session_by_port(i['ip'], i['bgp']['neighbour_id'], 179)
                    if session is None:
                        i['bgp']['state'] = 'CONNECT'
                        seq_num = randint(1, 2 ** 30)
                        src_port = randint(49152, 65535)
                        new_session = self.create_session(i['ip'], i['bgp']['neighbour_id'], src_port, 179, 'SYN-SENT', 'OUT', seq_num)

                        packet_syn = self.craft_tcp(i['ip'], i['bgp']['neighbour_id'], new_session, 'S')
                        new_session['seq_num'] += 1
                        i['obj'].send_data(packet_syn)
                    elif session['state'] == 'CLOSING':
                        session['closing_counter'] = session['closing_counter'] - 1

                        if session['closing_counter'] == 0:
                            to_del = None
                            for j in range(len(self.sessions[i['ip']][i['bgp']['neighbour_id']]['tcp'])):
                                if self.sessions[i['ip']][i['bgp']['neighbour_id']]['tcp'][j] == session:
                                    to_del = j

                            self.sessions[i['ip']][i['bgp']['neighbour_id']]['tcp'].pop(to_del)
                    else:
                        # SEND SECTION
                        # KEEP ALIVE, UPDATE, OPEN
                        # если сессия в BGP статусе ESTABLISHED уменьшаем KEEPALIVE таймер
                        # если он 0 - отправляем пакет KEEPALIVE
                        # если есть изменения в состоянии интерфейсов - отправляем UPDATE
                        if i['bgp']['state'] == 'ACTIVE' and session['direction'] == 'OUT':
                            # если мы инициировали сессию - и статус BGP ACTIVE направляем OPEN, меняем статус на OPEN SENT
                            packet = self.craft_tcp(i['ip'], i['bgp']['neighbour_id'], session)
                            # type=1 means OPEN
                            # type=2 means UPDATE packet will be the BGP Payload, marker field is for authentication.
                            # max hex int (all f) are used for no auth.
                            # update packet consist of path attributes and NLRI (Network layer reachability information),
                            # type_code in path attributes is for which type of path attribute it is. [more][3]

                            # NLRI_PREFIX = '10.110.99.0/24'
                            hdr = BGPHeader(type=1,
                                            marker=0xffffffffffffffffffffffffffffffff)

                            #up = BGPUpdate(path_attr=[
                            #    BGPPathAttr(type_flags=64, type_code=5, attribute=BGPPALocalPref(local_pref=100))],
                            #    nlri=BGPNLRI_IPv4(
                            #    prefix=NLRI_PREFIX))

                            op = BGPOpen(my_as=self.as_id, hold_time=90, bgp_id=i['ip'])

                            bgp = packet / hdr / op
                            i['obj'].send_data(bgp)
                            i['bgp']['state'] = 'OPEN SENT'
                            i['bgp']['open_time'] = 1
                            session['old_seq_num'] = session['seq_num']
                            session['seq_num'] = session['seq_num'] + len(bgp[TCP].payload)
                        elif i['bgp']['state'] == 'OPEN SENT':
                            if i['bgp']['open_time'] > 20:
                                session['seq_num'] = session['old_seq_num']
                                i['bgp']['state'] = 'ACTIVE'
                            else:
                                i['bgp']['open_time'] += 1
        sleep(0.4)

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
