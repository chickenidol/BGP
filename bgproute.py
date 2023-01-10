from tools import ip_to_int


class BGPRoute:
    def __init__(self, network, mask, next_hop, path, weight=0, status=0, source=None):
        self.mask = ip_to_int(mask)
        self.network = ip_to_int(network)
        self.network &= self.mask
        self.next_hop = ip_to_int(next_hop)
        self.weight = int(weight)

        self.path = []
        for as_num in path.split():
            self.path.append(int(as_num))

        self.source = source

        if not self.source:
            self.source = self.path[0]
