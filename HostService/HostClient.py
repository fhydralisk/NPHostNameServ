import commands


class HostClient(object):
    def __init__(self, address, hs_name, resolve_mac=False):
        self.ip = address[0]
        self.port = address[1]
        self.hs_name = hs_name
        self.mac = None
        if resolve_mac:
            self.mac = self.resolve_mac(self.ip)

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
    def resolve_mac(ip):
        # TODO: shall CHECK whether in same subnet first
        status, output = commands.getstatusoutput("arp -an |grep '(%s)'|awk -F' ' '{print $4}'" % ip)
        if status != 0:
            return None

        if len(output.split(':')) != 6:
            return None

        return output

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.ip == other.ip and self.hs_name == other.hs_name and self.mac == other.mac
