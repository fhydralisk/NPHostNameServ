import os, sys, traceback, commands, json, httplib2, time, threading, base64
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

loggerPath = "/usr/bin/logger"


def print_usage():
    print "Usage:"
    print "HostnameServ.py Port HostNameFile Deamon"


def hs_log(msg, tag="HostnameServ", debug_print=False, debug_trace=True):

    if debug_print:
        print msg
        try:
            traceback.print_exc()
        except ValueError:
            pass

    if isinstance(tag, basestring):
        tag = " -t " + tag
    else:
        tag = ""

    if debug_trace:
        msg = msg + "traceback:" + traceback.format_exc()

    msg = msg.replace('"', r'\"')
    commands.getstatusoutput(loggerPath + " " + tag + ' "' + msg + '"')


class HostnameServer(HTTPServer):

    STATE_ACTIVE = "Active"
    STATE_DEAD = "Dead"
    STATE_UPDATE_PENDING = "Updating"

    def __init__(self, mapfile, *args, **kwargs):
        self.mapping = self.open_mapfile(mapfile)
        self.mapStore = {}
        self.threadMapStore = threading.Thread(target=self.mapstore_checker)
        self.mapStoreLock = threading.RLock()
        self.mapStoreCheckInterval = 10
        self.mapStoreClientDeadTime = 60 * 60
        self.mapStoreClientKillTime = 60 * 60 * 2
        # self.mapStoreClientDeadTime = 10
        # self.mapStoreClientKillTime = 20
        self.threadMapStore.setDaemon(True)
        self.threadMapStore.start()

        HTTPServer.__init__(self, *args, **kwargs)

    def mapstore_checker(self):
        while True:
            self.mapStoreLock.acquire()
            try:
                for k, v in self.mapStore.items():
                    if time.time() - v["last_update"] > self.mapStoreClientKillTime:
                        hs_log("%s is dead completely, remove it from list" % k)
                        del self.mapStore[k]

                    elif v["state"] != self.STATE_DEAD and time.time() - v["last_update"] > self.mapStoreClientDeadTime:
                        hs_log("%s is dying, changing status to DEAD" % k)
                        v["state"] = self.STATE_DEAD
            except:
                hs_log("Unexcepted error at %s %s" % (__file__, sys._getframe().f_lineno))
            finally:
                self.mapStoreLock.release()

            time.sleep(self.mapStoreCheckInterval)

    def handle_hs_message(self, hs_name, ip_addr):
        if hs_name not in self.mapping["hostmap"]:
            raise NameError

        if hs_name not in self.mapStore or self.mapStore[hs_name]["ip"] != ip_addr:
            # shall update ip address
            self.mapStoreLock.acquire()
            try:
                if hs_name not in self.mapStore:
                    self.mapStore[hs_name] = {
                        "ip_memory": ip_addr,
                        "ip": "0.0.0.0",
                        "state": self.STATE_UPDATE_PENDING,
                        "last_update": time.time()
                    }
                else:
                    self.mapStore[hs_name]["ip_memory"] = ip_addr
                    self.mapStore[hs_name]["state"] = self.STATE_UPDATE_PENDING
                    self.mapStore[hs_name]["last_update"] = time.time()
            except:
                hs_log("Unexcepted error at %s %s" % (__file__, sys._getframe().f_lineno))
            finally:
                self.mapStoreLock.release()

            self.update_remote_ns(hs_name, ip_addr)

            self.mapStoreLock.acquire()
            try:
                self.mapStore[hs_name]["ip"] = ip_addr
                self.mapStore[hs_name]["state"] = self.STATE_ACTIVE
            except:
                hs_log("Unexcepted error at %s %s" % (__file__, sys._getframe().f_lineno))
            finally:
                self.mapStoreLock.release()

        else:
            self.mapStoreLock.acquire()
            try:
                self.mapStore[hs_name]["last_update"] = time.time()
                self.mapStore[hs_name]["state"] = self.STATE_ACTIVE
            except:
                hs_log("Unexcepted error at %s %s" % (__file__, sys._getframe().f_lineno))
            finally:
                self.mapStoreLock.release()

    def update_remote_ns(self, hs_name, ip_addr):
        hs_log("Trying to update %s with ip %s" % (hs_name, ip_addr))
        remote_hs = self.mapping["hostmap"][hs_name]
        dynns_name = remote_hs[0]
        dynns_serv_name = remote_hs[1]
        dynns_serv_dict = self.mapping["dyndnsserver"][dynns_serv_name]
        username = dynns_serv_dict["username"] if "username" in dynns_serv_dict else None
        password = dynns_serv_dict["password"] if "password" in dynns_serv_dict else None

        request_ok = False
        script_ok = False

        if "URL" in dynns_serv_dict and dynns_serv_dict["URL"] is not None:
            method = dynns_serv_dict["method"]
            request = httplib2.Http(timeout=10, disable_ssl_certificate_validation=True)

            headers = None
            content = None
            url = self.replace_fields(dynns_serv_dict["URL"],
                                      dynns_name, ip_addr, username, password)

            if "headers" in dynns_serv_dict:
                headers = {}
                headers_orig = dynns_serv_dict["headers"]
                for k, v in headers_orig.items():
                    headers[self.replace_fields(k, dynns_name, ip_addr, username, password)] = \
                        self.replace_fields(v, dynns_name, ip_addr, username, password)

            if "auth" in dynns_serv_dict:
                if "username" in dynns_serv_dict["auth"] and "password" in dynns_serv_dict["auth"]:
                    request.add_credentials(
                        self.replace_fields(dynns_serv_dict["auth"]["username"],
                                            dynns_name, ip_addr, username, password),
                        self.replace_fields(dynns_serv_dict["auth"]["password"],
                                            dynns_name, ip_addr, username, password)
                    )

            if method != "GET" and "content" in dynns_serv_dict and dynns_serv_dict["content"] is not None:
                content = self.replace_fields(dynns_serv_dict["content"],
                                              dynns_name, ip_addr, username, password)

            try:
                response, resp_content = request.request(url, method, content, headers)
                if response.status in [200, 202, 204]:
                    request_ok = True
            except Exception, e:
                hs_log("Request to Dyn dns failed: %s. Exception: %s" % (hs_name, str(e)))
                request_ok = False
        else:
            request_ok = True

        if "custom-script" in dynns_serv_dict and dynns_serv_dict["custom-script"] is not None:
            cmd = self.replace_fields(dynns_serv_dict["custom-script"],
                                      dynns_name, ip_addr, username, password)
            status, output = commands.getstatusoutput(cmd)
            if status == 0:
                script_ok = True
        else:
            script_ok = True

        if not (request_ok and script_ok):
            raise EnvironmentError

    def auth_and_get_status(self, user, passwd):
        if user == self.mapping["config"]["auth"]["username"] and passwd == self.mapping["config"]["auth"]["password"]:
            return json.dumps(self.mapStore, sort_keys=True, indent=4, separators=(',', ': '))
        else:
            return None

    @staticmethod
    def replace_fields(text, host=None, ipaddr=None, username=None, password=None):
        ret = text

        ret = ret.replace("%host", host) if host is not None else ret
        ret = ret.replace("%ipaddr", ipaddr) if ipaddr is not None else ret
        ret = ret.replace("%username", username) if username is not None else ret
        ret = ret.replace("%password", password) if password is not None else ret

        return ret

    @staticmethod
    def open_mapfile(mapfile):
        try:
            f = open(mapfile, 'r')
        except IOError:
            hs_log("Can not find mapping file %s" % mapfile)
            sys.exit(404)

        try:
            mapping = json.load(f)
        except ValueError:
            hs_log("Can not parse mapping file")
            sys.exit(500)
        finally:
            f.close()

        try:
            for v in mapping["hostmap"].values():
                if v[1] not in mapping["dyndnsserver"]:
                    hs_log("%s not in dyndns list" % v[1])
                    raise KeyError

            for k, v in mapping["dyndnsserver"].items():
                if ("method" not in v or v["method"] not in ["GET", "POST", "PUT", "DELETE"]) \
                        and ("URL" in v and v["URL"] is not None):
                    hs_log('"method" not in %s while "URL" in dyndns server' % k)
                    raise ValueError

        except:
            hs_log("Error when parsing mapping file")
            sys.exit(500)

        return mapping


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
                    self.server.handle_hs_message(hs_name, self.client_address[0])
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
                    # print self.headers["authorization"]

                    challenge = self.headers["authorization"]
                    if not challenge.startswith("Basic "):
                        self.send_error(401)
                    challenge = challenge[len("Basic "):]
                    try :
                        auth = base64.b64decode(challenge)
                        user, passwd = auth.split(':')
                        content = self.server.auth_and_get_status(user, passwd)
                        if content is not None:
                            self.write_common_header(200)
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
