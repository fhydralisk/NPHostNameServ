import json
import base64

import BaseHTTPServer
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from LinuxLocalMacAddrGetter import LinuxLocalMacAddrGetter


class RemoteMacAddrServer(HTTPServer):

    def __init__(self, config={"auth": {"username": "admin", "password": "admin"}}, *args, **kwargs):
        self.config = config
        self.mac_getter = LinuxLocalMacAddrGetter({})
        HTTPServer.__init__(self, *args, **kwargs)

    def finish_request(self, request, client_address):
        request.settimeout(1)
        # "super" can not be used because BaseServer is not created from object
        BaseHTTPServer.HTTPServer.finish_request(self, request, client_address)

    def auth(self, user, passwd):
        if user == self.config["auth"]["username"] and passwd == self.config["auth"]["password"]:
            return True

        return False


class RemoteMacAddrHandler(BaseHTTPRequestHandler):

    def write_common_header(self, response_code=200, content_type=None, other_fields=None):
        self.protocol_version = 'HTTP/1.1'
        self.send_response(response_code)
        if content_type is not None:
            self.send_header('Content-Type', content_type)

        if isinstance(other_fields, dict):
            for k, v in other_fields.items():
                self.send_header(k, v)

        self.end_headers()

    def auth(self, code_succeed=200, content_type_succeed=None, headers_succeed=None):
        if "authorization" not in self.headers:
            self.write_common_header(401, other_fields={'WWW-Authenticate':'Basic realm="Test"'})
            return False

        challenge = self.headers["authorization"]
        if not challenge.startswith("Basic "):
            self.send_error(401)
            return False

        b64up = challenge[len("Basic "):]
        try:
            auth = base64.b64decode(b64up)
            user, passwd = auth.split(':')
            if self.server.auth(user, passwd):
                self.write_common_header(code_succeed, content_type=content_type_succeed,
                                         other_fields=headers_succeed)
                return True
            else:
                self.send_error(401)
                return False

        except:
            self.send_error(401)
            return False

    def do_GET(self):
        # print self.path
        path_components = self.path.split("/")
        if len(path_components) <= 1 or len(path_components) >= 3:
            self.write_common_header(404)
        else:
            p2 = path_components[1]
            if p2.startswith('get_mac.do?ip='):
                ip = p2.replace("get_mac.do?ip=", "")
                mac = self.server.mac_getter.get_mac_of_ip(ip)
                if mac is not None:
                    resp_obj = {
                        "Result": "OK",
                        "MAC": mac
                    }
                else:
                    resp_obj = {
                        "Result": "Failed"
                    }

                self.write_common_header()
                self.wfile.write(json.dumps(resp_obj))
            else:
                self.send_error(404)
