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
        self.updater.run_checker()
        HTTPServer.__init__(self, *args, **kwargs)

    def handle_hs_message(self, client):
        self.updater.handle_client_heartbeat(client)

    def auth_and_get_status(self, user, passwd):
        config = self.updater.get_config()
        if user == config["auth"]["username"] and passwd == config["auth"]["password"]:
            return json.dumps(self.updater.get_host_status(), sort_keys=True, indent=4, separators=(',', ': '))
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

    def do_GET(self):
        # print self.path
        path_components = self.path.split("/")
        if len(path_components) <= 1 or len(path_components) >= 3:
            self.write_common_header(404)
        else:
            p2 = path_components[1]
            if p2.startswith('?name='):
                hs_name = p2.replace("?name=","")
                try:
                    self.server.handle_hs_message(HostClient(self.client_address, hs_name, resolve_mac=True))
                except NameError:
                    hs_log("Unexist user %s attempt to update ip address %s" % (hs_name, self.client_address[0]))
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
                if "authorization" not in self.headers:
                    self.write_common_header(401, other_fields={'WWW-Authenticate':'Basic realm="Test"'})
                else:
                    challenge = self.headers["authorization"]
                    if not challenge.startswith("Basic "):
                        self.send_error(401)
                    challenge = challenge[len("Basic "):]
                    try :
                        auth = base64.b64decode(challenge)
                        user, passwd = auth.split(':')
                        content = self.server.auth_and_get_status(user, passwd)
                        if content is not None:
                            self.write_common_header(200,content_type="application/json")
                            self.wfile.write(content)
                        else:
                            self.send_error(401)

                    except:
                        self.send_error(401)
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
