import threading

from examples import conf1, conf3, conf2




conf2()

def test_send():
    packet = IP(dst="8.8.8.8", ttl=20) / ICMP()
    #Ether()/IP()/TCP()
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24")
    answer, pp = scapy.sr(packet, timeout=20)
    for s, r in answer:
        if r.haslayer(IP):
            resp = IP(raw(r))
            print(export_object(resp))
