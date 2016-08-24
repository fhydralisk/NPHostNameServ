import os, sys, json, base64
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from HostnameUpdater import HostnameUpdater
from Hslog import hs_log
from HostClient import HostClient


def print_usage():
    print "Usage:"
    print "HostnameServ.py Port HostNameFile Deamon"


class HostnameServer(HTTPServer):

    def __init__(self, mapfile, *args, **kwargs):
        self.updater = HostnameUpdater(mapfile)
        self.updater.run_updater(restart=False)
        HTTPServer.__init__(self, *args, **kwargs)

    def handle_hs_message(self, client):
        self.updater.handle_client_heartbeat(client)

    def handle_restart_command(self):
        self.updater.run_updater(restart=True)
        return True

    def auth(self, user, passwd):
        config = self.updater.get_config()
        if user == config["auth"]["username"] and passwd == config["auth"]["password"]:
            return True

        return False

    def get_status_json(self):
        return json.dumps(self.updater.get_host_status(), sort_keys=True, indent=4, separators=(',', ': '))

    def auth_and_get_status(self, user, passwd):
        if self.auth(user, passwd):
            return self.get_status_json()
        else:
            return None


class HostnameRequestHandler(BaseHTTPRequestHandler):

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
            if p2.startswith('?name='):
                hs_name = p2.replace("?name=", "")
                try:
                    self.server.handle_hs_message(HostClient(self.client_address, hs_name, resolve_mac=True))
                except NameError:
                    hs_log("Nonexist user %s attempt to update ip address %s" % (hs_name, self.client_address[0]))
                    self.send_error(404)
                except EnvironmentError:
                    # dyn server unreachable or custom script exec failed
                    self.send_error(503)
                except Exception, e:
                    hs_log("Failed to update")
                    self.write_common_header(500, content_type="text/plain")
                    self.wfile.write(str(e))
                else:
                    self.write_common_header()
                    self.wfile.write("OK")
            elif p2 == "state.look":
                if self.auth(code_succeed=200, content_type_succeed="application/json"):
                    self.wfile.write(self.server.get_status_json())
            elif p2 == "restart.do":
                if self.auth(code_succeed=200, content_type_succeed="application/json"):
                    result = self.server.handle_restart_command()
                    if result:
                        ret_rpc = {
                            "Result": "OK"
                        }
                    else:
                        ret_rpc = {
                            "Result": "Failed"
                        }

                    self.wfile.write(json.dumps(ret_rpc, sort_keys=True, indent=4, separators=(',', ': ')))
            else:
                self.send_error(404)


def deamon():
    if os.fork() > 0:
        sys.exit(0)

    os.setsid()
    os.chdir("/")
    os.umask(0)

    if os.fork() > 0:
        sys.exit(0)

    sys.stdout.flush()
    sys.stderr.flush()

    si = file('/dev/null', 'r')
    so = file('/dev/null', 'a+')
    serr = file('/dev/null', 'a+')
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(serr.fileno(), sys.stderr.fileno())

if len(sys.argv) != 4:
    print_usage()
    exit(1)

port = int(sys.argv[1])
mapFile = sys.argv[2]
deamonlize = sys.argv[3]
if deamonlize.upper() == "TRUE" or deamonlize.upper() == "YES" or deamonlize == "1":
    deamon()

hostServer = HostnameServer(mapFile, ('', port), HostnameRequestHandler)
hs_log("Starting HostnameServer...")
try:
    hostServer.serve_forever()
except:
    hs_log("HostnameServ deamon unexceptly stopped.")
    sys.exit(3)
