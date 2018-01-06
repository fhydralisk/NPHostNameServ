import commands


class HostClient(object):
    def __init__(self, address, hs_name, mac_resolver=None, mac=None):
        self.ip = address[0]
        self.port = address[1]
        self.hs_name = hs_name
        self.mac = mac
        if mac_resolver is not None:
            self.mac = self.resolve_mac(self.ip, mac_resolver)

    def get_address(self):
        ret = {
            "ip": self.ip,
            "port": self.port,
            "mac": self.mac
        }

        return ret

    def get_hs_name(self):
        return self.hs_name

    @staticmethod
    def resolve_mac(ip, mac_resolver):
        return mac_resolver.get_mac_of_ip(ip)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and \
               self.ip == other.ip and \
               self.hs_name == other.hs_name and \
               self.mac == other.mac
