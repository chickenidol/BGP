from tools import ip_to_int


class Route:
    def __init__(self, network, mask, gw, source, interface=0, metric=0, bgp_route=None):
        self.mask = ip_to_int(mask)
        self.network = ip_to_int(network)
        self.network &= self.mask
        self.gw = ip_to_int(gw)
        self.interface = ip_to_int(interface)

        if source == 'C' or source == 'B':
            self.source = source
        else:
            self.source = 'U'

        self.metric = int(metric)

        self.bgp_route = None

        if bgp_route and self.source == 'B':
            self.bgp_route = bgp_route
