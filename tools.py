import ipaddress
import threading

from netaddr import IPAddress
from scapy.compat import bytes_base64
from scapy.contrib.bgp import BGPPAAS4BytesPath, BGPPathAttr, BGPPALocalPref, BGPUpdate, BGPNLRI_IPv4, BGPPAOrigin, \
    BGPPANextHop, BGPPAMultiExitDisc

from scapy.layers.inet import IP, ICMP, Ether, TCP
from scapy.modules import six
import zlib


def netmask_to_bits(mask):
    return IPAddress(mask).netmask_bits()


def ip_to_int(address):
    if isinstance(address, str):
        return int(ipaddress.ip_address(address))
    else:
        return int(address)


def int_to_ip(address):
    return str(ipaddress.ip_address(address))


def cidr_to_netmask(cidr):
    cidr = int(cidr)
    mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return (str((0xff000000 & mask) >> 24) + '.' +
            str((0x00ff0000 & mask) >> 16) + '.' +
            str((0x0000ff00 & mask) >> 8) + '.' +
            str((0x000000ff & mask)))


def craft_bgp_update(origin, as_path, next_hop, nlri):
    path = []
    for a in as_path:
        path.append(BGPPAAS4BytesPath().ASPathSegment(segment_type=2, segment_value=[a]))

    set_as = BGPPathAttr(
        type_flags="Transitive",
        type_code="AS_PATH",
        attribute=BGPPAAS4BytesPath(
            segments=path
        )
    )

    set_origin = BGPPathAttr(type_flags="Transitive", type_code="ORIGIN", attribute=[BGPPAOrigin(origin=origin)])
    set_nexthop = BGPPathAttr(type_flags="Transitive", type_code="NEXT_HOP",
                              attribute=[BGPPANextHop(next_hop=next_hop)])
    set_med = BGPPathAttr(type_flags="Optional", type_code="MULTI_EXIT_DISC", attribute=[BGPPAMultiExitDisc(med=0)])
    set_localpref = BGPPathAttr(type_flags="Transitive", type_code="LOCAL_PREF",
                                attribute=[BGPPALocalPref(local_pref=100)])

    bgp_update = BGPUpdate(
        withdrawn_routes_len=0,
        path_attr=[set_origin, set_as, set_nexthop, set_med, set_localpref],
        nlri=[BGPNLRI_IPv4(prefix=nlri)]
    )

    return bgp_update


def del_from_list(arr, to_del):
    for i in sorted(to_del, reverse=True):
        del arr[i]


def craft_tcp(src_ip, dst_ip, sport, dport, seq_num, ack_num, flags=''):
    packet = IP(src=src_ip, dst=dst_ip, ttl=20) / TCP(
        sport=sport,
        dport=dport,
        flags=flags,
        seq=seq_num,
        ack=ack_num)
    return packet


def export_scapy(obj):
    return bytes_base64(zlib.compress(six.moves.cPickle.dumps(obj, 2), 9))


def ip_in_network(network, mask, ip):
    if (ip & mask) == network:
        return True
    return False


debug_print_lock = threading.Lock()
debug_level = 5


def debug_message(severity, source, procedure, message):
    with debug_print_lock:
        if severity <= debug_level:
            print(f'[{severity}]', source + '.', message)
