import urllib2
import json
from utils import hs_log


class RemoteMacAddrGetter(object):
    """
    This Mac addr getter gets mac address from the router.
    """

    def __init__(self, config):
        """

        :param config: The config of addr getter
        """
        self.config = config

    def get_mac_of_ip(self, ip):
        """
        Get mac
        :param ipaddr: ip address
        :return: mac address
        """
        try:
            resp = urllib2.urlopen("%s?ip=%s" % (self.config["rpc_url"], ip), timeout=1)
            resp_obj = json.loads(resp.read())
            if resp_obj["Result"] == "OK":
                return resp_obj["MAC"]
        except Exception, e:
            hs_log("Cannot connect to get mac rpc. Exception " + str(e))
            return None
