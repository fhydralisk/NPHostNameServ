import commands


class LinuxLocalMacAddrGetter(object):
    def __init__(self, config):
        self.config = config

    def get_mac_of_ip(self, ip):
        status, output = commands.getstatusoutput("arp -an |grep '(%s)'|awk -F' ' '{print $4}'" % ip)
        if status != 0:
            return None

        if len(output.split(':')) != 6:
            return None

        return output
