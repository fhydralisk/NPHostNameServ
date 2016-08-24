import json, sys, commands, threading, time, httplib2
from Hslog import hs_log


class Host(object):
    STATE_ACTIVE = "Online"
    STATE_DEAD = "Dead"
    STATE_OFFLINE = "Offline"
    STATE_UPDATE_NONE = "N/A"
    STATE_UPDATE_PENDING = "Updating"
    STATE_UPDATE_OK = "OK"
    STATE_UPDATE_BAD = "Bad"
    DEFAULT_DEAD_INTERVAL = 900

    def __init__(self, hs_name, info, dict_dnss, dict_scripts, dead_interval=None):
        self.hs_name = hs_name
        self.dnss = {}
        self.scripts = {}
        self.status = self.STATE_OFFLINE
        self.last_update = 0
        self.last_client = None
        self.deadInterval = dead_interval if isinstance(dead_interval, int) else self.DEFAULT_DEAD_INTERVAL

        if "DNS" in info:
            for dns_info in info["DNS"]:
                dns_profile = dns_info["Profile"]
                dns_hostname = dns_info["Hostname"]
                self.dnss[dns_profile] = {
                    "DNS_OBJ": dict_dnss[dns_profile],
                    "DNS_HOSTNAME": dns_hostname,
                    "UPDATE_TIME": 0,
                    "State": self.STATE_UPDATE_NONE
                }

        if "Script" in info:
            for script_info in info["Script"]:
                script_profile = script_info["Profile"]
                script_param = script_info["Param"]
                self.scripts[script_profile] = {
                    "SCRIPT_OBJ": dict_scripts[script_profile],
                    "SCRIPT_PARAM": script_param,
                    "UPDATE_TIME": 0,
                    "State": self.STATE_UPDATE_NONE
                }

    def execute_script(self, script_profile, client):
        script = self.scripts[script_profile]
        script["SCRIPT_OBJ"].execute(script["SCRIPT_PARAM"], client)

    def execute_dns(self, dns_profile, client):
        dns = self.dnss[dns_profile]
        dns["DNS_OBJ"].execute(dns["DNS_HOSTNAME"], client)

    def set_state(self, state):
        if state not in [self.STATE_ACTIVE, self.STATE_DEAD, self.STATE_OFFLINE]:
            raise ValueError

        self.status = state

    def get_status_all(self):
        ret = {
            "Status": self.status,
            "DNS": {k: {"hostname": v["DNS_HOSTNAME"], "last_update": v["UPDATE_TIME"], "State":v["State"]}
                    for k, v in self.dnss.items()},

            "Script": {k: {"last_update": v["UPDATE_TIME"], "State": v["State"]}
                       for k, v in self.scripts.items()},

            "Last_update": self.last_update,

        }
        if self.last_client is not None:
            ret["last_address"] = {k: v for k, v in self.last_client.get_address().items() if k != "port"}

        return ret

    def check_dead(self):
        if self.is_online():
            if time.time() - self.last_update > self.deadInterval:
                self.status = self.STATE_DEAD
                hs_log("%s is dying." % self.hs_name)

    def is_online(self):
        return self.status in [self.STATE_ACTIVE]

    def maybe_refresh_dns_and_scripts(self, force=False, client=None, from_hb=False):
        client_real = client if client is not None else self.last_client
        if client_real is None:
            hs_log("Trying to refresh a not existing client of %s, how can it happen?" % self.hs_name)
            return
        if not client_real.__eq__(self.last_client):
            self.last_client = client_real
            force = True
            hs_log("Client of %s have changed, updating..." % self.hs_name)

        if from_hb:
            self.last_update = time.time()
            self.status = self.STATE_ACTIVE

        for profile_name, dict_dns in self.dnss.items():
            dns_obj = dict_dns["DNS_OBJ"]
            dns_hostname = dict_dns["DNS_HOSTNAME"]
            update_time = dict_dns["UPDATE_TIME"]
            state = dict_dns["State"]
            if force or state == self.STATE_UPDATE_PENDING or dns_obj.is_timeout(update_time, time.time()):
                if dns_obj.is_timeout(update_time, time.time()):
                    hs_log("%s DNS timeout, peform updating..." % self.hs_name)
                dict_dns["State"] = self.STATE_UPDATE_PENDING
                result = dns_obj.execute(dns_hostname, client_real)
                if result:
                    dict_dns["UPDATE_TIME"] = time.time()
                    dict_dns["State"] = self.STATE_UPDATE_OK

        for profile_name, dict_script in self.scripts.items():
            script_obj = dict_script["SCRIPT_OBJ"]
            script_param = dict_script["SCRIPT_PARAM"]
            update_time = dict_script["UPDATE_TIME"]
            if force or script_obj.is_timeout(update_time, time.time()):
                if script_obj.is_timeout(update_time, time.time()):
                    hs_log("%s Script timeout, peform updating..." % self.hs_name)
                result = script_obj.execute(script_param, client_real)
                dict_script["State"] = self.STATE_UPDATE_OK if result else self.STATE_UPDATE_BAD


class _Runner(object):
    def __init__(self):
        self.timeout = 0

    @staticmethod
    def replace_fields(text, host=None, ipaddr=None, username=None, password=None):
        ret = text

        ret = ret.replace("%host", host) if host is not None else ret
        ret = ret.replace("%ipaddr", ipaddr) if ipaddr is not None else ret
        ret = ret.replace("%username", username) if username is not None else ret
        ret = ret.replace("%password", password) if password is not None else ret

        return ret

    def execute(self, param, client):
        raise Exception("Not Implemented")

    def is_timeout(self, time_last, time_now):
        if self.timeout == 0:
            return False
        return time_now - time_last > self.timeout


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

        request = httplib2.Http(timeout=10, disable_ssl_certificate_validation=True)

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


class Script(_Runner):
    def __init__(self, profile_name, info):
        _Runner.__init__(self)
        self.profile_name = profile_name
        self.commandline = info["command"]
        self.timeout = info["timeout"]

    def execute(self, param, client):
        commandline_real = self.commandline + " " + self.replace_fields(param, ipaddr=client.get_address()["ip"])
        status, output = commands.getstatusoutput(commandline_real)
        hs_log("Script %s run, statue=%d, output=%s" % (commandline_real, status, output))
        return status == 0


class HostnameUpdater(object):
    DEFAULT_CHECK_INTERVAL = 5

    def __init__(self, filename):
        self.hosts = {}
        self.dnss = {}
        self.scripts = {}
        self.mapping = {}
        self.threadMapStore = None
        self.checkInterval = self.DEFAULT_CHECK_INTERVAL
        self.open_mapfile(filename)

    def get_config(self):
        return self.mapping["config"]

    def get_host_status(self):
        return {k: v.get_status_all() for k, v in self.hosts.items()}

    def open_mapfile(self, filename):
        try:
            f = open(filename, 'r')
        except IOError:
            hs_log("Can not find mapping file %s" % filename)
            sys.exit(404)

        try:
            mapping = json.load(f)
        except ValueError:
            hs_log("Can not parse mapping file")
            sys.exit(500)
        finally:
            f.close()

        self.mapping = mapping
        try:
            if "scripts" in self.mapping:
                for script in self.mapping["scripts"]:
                    self.scripts[script] = Script(script, self.mapping["scripts"][script])

            if "dyndnsserver" in self.mapping:
                for dyndns in self.mapping["dyndnsserver"]:
                    self.dnss[dyndns] = DNS(dyndns, self.mapping["dyndnsserver"][dyndns])

            for host in self.mapping["hostmap"]:
                self.hosts[host] = Host(host, self.mapping["hostmap"][host], self.dnss, self.scripts)
        except:
            hs_log("Error when parsing mapping file")
            sys.exit(500)

    def handle_client_heartbeat(self, client):
        if self._validate_client(client):
            self._execute_script_and_nsupdate(client)
        else:
            raise EnvironmentError

    def _validate_client(self, client):
        if client.get_hs_name() in self.hosts:
            return True

    def _execute_script_and_nsupdate(self, client):
        if client.get_hs_name() not in self.hosts:
            # TODO: Now it is a bug
            return False

        self.hosts[client.get_hs_name()].maybe_refresh_dns_and_scripts(client=client, from_hb=True)
        return True

    def run_checker(self):
        if self.threadMapStore is None:
            self.threadMapStore = threading.Thread(target=self.mapstore_checker)
            self.threadMapStore.setDaemon(True)
            self.threadMapStore.start()

    def mapstore_checker(self):
        while True:
            try:
                for hs_name, host in self.hosts.items():
                    host.check_dead()
                    if host.is_online():
                        host.maybe_refresh_dns_and_scripts()
            except:
                hs_log("Unexcepted error at %s %s" % (__file__, sys._getframe().f_lineno))

            time.sleep(self.checkInterval)
