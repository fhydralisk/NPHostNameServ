import json
import base64

import BaseHTTPServer
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

from TsLog import ts_log


def print_usage():
    print "Usage:"
    print "HostnameServ.py Port HostNameFile Deamon"


class TempSensWebServer(HTTPServer):

    def __init__(self, coordinator, *args, **kwargs):
        self.coordinator = coordinator
        HTTPServer.__init__(self, *args, **kwargs)

    def finish_request(self, request, client_address):
        request.settimeout(2)
        # "super" can not be used because BaseServer is not created from object
        BaseHTTPServer.HTTPServer.finish_request(self, request, client_address)

    def auth(self, user, passwd):
        auth = self.coordinator.get_auth()
        if user == auth["username"] and passwd == auth["password"]:
            return True

        return False

    def get_nodes_info_json(self):
        return json.dumps(self.coordinator.get_nodes_info(), sort_keys=True, indent=4, separators=(',', ': '))


class TempSensRequestHandler(BaseHTTPRequestHandler):

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
            if p2 == "node.info":
                try:
                    if self.auth(code_succeed=200, content_type_succeed="application/json"):
                        self.wfile.write(self.server.get_nodes_info_json())
                except:
                    ts_log("Unexpected error when getting nodeinfo")
                    self.send_error(500)

            else:
                self.send_error(404)
