import httplib2
from Runner import _Runner
from utils import hs_log


DNS_TIMEOUT = 10


class DNS(_Runner):
    def __init__(self, profile_name, info):
        _Runner.__init__(self)
        self.profile_name = profile_name
        self.username = info["username"] if "username" in info else None
        self.password = info["password"] if "password" in info else None
        self.method = info["method"]
        self.url = info["URL"]
        self.headers = info["headers"] if "headers" in info else None
        self.auth = info["auth"] if "auth" in info else None
        self.content = info["content"] if "content" in info else None
        self.timeout = info["timeout"]

    def execute(self, param, client):
        # dynns_serv_dict = self.mapping["dyndnsserver"][dynns_serv_name]
        username = self.username
        password = self.password
        method = self.method
        headers = self.headers
        content = self.content
        auth = self.auth
        url = self.url
        dynns_name = param
        ip_addr = client.get_address()["ip"]

        request = httplib2.Http(timeout=DNS_TIMEOUT, disable_ssl_certificate_validation=True)

        url = self.replace_fields(url, dynns_name, ip_addr, username, password)
        request_ok = False

        headers_real = None
        if headers is not None:
            for k, v in headers.items():
                headers[self.replace_fields(k, dynns_name, ip_addr, username, password)] = \
                    self.replace_fields(v, dynns_name, ip_addr, username, password)

        if auth is not None:
            if "username" in auth and "password" in auth:
                request.add_credentials(
                    self.replace_fields(auth["username"],
                                        dynns_name, ip_addr, username, password),
                    self.replace_fields(auth["password"],
                                        dynns_name, ip_addr, username, password)
                )

        content_real = None
        if method != "GET" and content is not None:
            content_real = self.replace_fields(content,
                                               dynns_name, ip_addr, username, password)

        try:
            response, resp_content = request.request(url, method, content_real, headers_real)
            if response.status in [200, 202, 204]:
                request_ok = True
            else:
                hs_log("Request to Dyn dns failed: %s. Exception: %s" % client.get_hs_name())
        except Exception, e:
            hs_log("Request to Dyn dns failed: %s. Exception: %s" % (client.get_hs_name(), str(e)))
            request_ok = False

        return request_ok
