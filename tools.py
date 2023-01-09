import ipaddress
from netaddr import IPAddress
from scapy.contrib.bgp import BGPPAAS4BytesPath, BGPPathAttr, BGPPALocalPref, BGPUpdate, BGPNLRI_IPv4, BGPPAOrigin, \
    BGPPANextHop, BGPPAMultiExitDisc


def netmask_to_bits(mask):
    return IPAddress('255.255.255.0').netmask_bits()


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
  return (str( (0xff000000 & mask) >> 24)   + '.' +
          str( (0x00ff0000 & mask) >> 16)   + '.' +
          str( (0x0000ff00 & mask) >> 8)    + '.' +
          str( (0x000000ff & mask)))


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
    set_nexthop = BGPPathAttr(type_flags="Transitive", type_code="NEXT_HOP", attribute=[BGPPANextHop(next_hop=next_hop)])
    set_med = BGPPathAttr(type_flags="Optional", type_code="MULTI_EXIT_DISC", attribute=[BGPPAMultiExitDisc(med=0)])
    set_localpref = BGPPathAttr(type_flags="Transitive", type_code="LOCAL_PREF",
                               attribute=[BGPPALocalPref(local_pref=100)])

    bgp_update = BGPUpdate(
        withdrawn_routes_len=0,
        path_attr=[set_origin, set_as, set_nexthop, set_med, set_localpref],
        nlri=[BGPNLRI_IPv4(prefix=nlri)]
    )

    return bgp_update
