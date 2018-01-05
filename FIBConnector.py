import urllib2, base64, json
from utils import hs_log


class FIBConnector(object):
    """
    The Connector to FIB for getting clients and updating DNS.
    """
    def __init__(self, config):
        self.url_get_client = config["urls"]["get_client_url"]
        self.url_update_dns = config["urls"]["update_url"]
        self.url_get_serial = config["urls"]["get_serial"]
        self.auth = config["auth"]

    def get_response(self, url, data=None, should_auth=True, timeout=10):
        request = urllib2.Request(url, data)

        if should_auth:
            base64string = base64.b64encode('%s:%s' % (self.auth["username"], self.auth["password"]))
            request.add_header("Authorization", "Basic %s" % base64string)

        result = urllib2.urlopen(request, timeout=timeout)
        return json.loads(result.read())

    def get_clients(self):
        """
        Get all clients.
        :return: All clients if succeed, otherwise None
        """
        try:
            client_config = self.get_response(self.url_get_client)
            return client_config
        except Exception, e:
            hs_log("Unexpected exception in get_clients: %s" % str(e))
            return None

    def get_serial(self):
        try:
            return self.get_response(self.url_get_serial)
        except Exception, e:
            hs_log("Unexpected exception in get_serial: %s" % str(e))
            return None

    def update_dns(self, names, ips):
        if len(names) != len(ips):
            return None

        # to request string
        try:
            req_str = "?names=%s&ips=%s" % ('|'.join(names), '|'.join(ips))
            result = self.get_response(self.url_update_dns + req_str)
            return result
        except Exception, e:
            hs_log("Unexpected exception in update_dns: %s" % str(e))
            return None
