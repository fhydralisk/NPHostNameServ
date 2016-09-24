import commands
import httplib2
import json
import sys
import threading
import time

from Utils.Hslog import hs_log

DNS_TIMEOUT = 10


def format_timestamp(timestamp):
    l_time = time.gmtime(timestamp + 8 * 60 * 60)
    return time.strftime("%Y-%m-%d %H:%M:%S", l_time)


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
        self.hsName = hs_name
        self.dnss = {}
        self.scripts = {}
        self.status = self.STATE_OFFLINE
        self.lastUpdate = 0
        self.lastClient = None
        self.validateMac = None
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

        if "Validate" in info:
            validate = info["Validate"]
            if "MAC" in validate:
                self.validateMac = \
                    [m.lower() for m in validate["MAC"] if isinstance(m, basestring) and len(m.split(":")) == 6]

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

    def get_status_all(self, format_time=True):
        ret = {
            "Status": self.status,
            "DNS": {k: {"hostname": v["DNS_HOSTNAME"],
                        "last_update": format_timestamp(v["UPDATE_TIME"]) if format_time else v["UPDATE_TIME"],
                        "State": v["State"]}
                    for k, v in self.dnss.items()},

            "Script": {k: {"last_update": format_timestamp(v["UPDATE_TIME"]) if format_time else v["UPDATE_TIME"],
                           "State": v["State"]}
                       for k, v in self.scripts.items()},

            "Last_update": format_timestamp(self.lastUpdate) if format_time else self.lastUpdate,

        }
        if self.lastClient is not None:
            ret["last_address"] =\
                {k: v for k, v in self.lastClient.get_address().items() if k != "port" and v is not None}
        elif self.validateMac is not None:
            ret["mac_address_maybe"] = self.validateMac

        return ret

    def check_dead(self):
        if self.is_online():
            if time.time() - self.lastUpdate > self.deadInterval:
                self.status = self.STATE_DEAD
                hs_log("%s is dying." % self.hsName)

    def is_online(self):
        return self.status in [self.STATE_ACTIVE]

    def validate_client(self, client):
        if self.validateMac is not None:
            client_mac = client.get_address()["mac"]
            if client_mac is None or client_mac not in self.validateMac:
                return False

        return True

    def maybe_refresh_dns_and_scripts(self, force=False, client=None, from_hb=False):
        def shall_update(fc, st, ut, runner):
            return fc or \
                   (st != self.STATE_UPDATE_PENDING and (st == self.STATE_UPDATE_BAD or
                                                         runner.is_timeout(ut, time.time())))

        client_real = client if client is not None else self.lastClient
        if client_real is None:
            hs_log("Trying to refresh a not existing client of %s, how can it happen?" % self.hsName)
            return
        if not client_real.__eq__(self.lastClient):
            self.lastClient = client_real
            force = True
            hs_log("Client of %s have changed, updating..." % self.hsName)

        if from_hb:
            self.lastUpdate = time.time()
            self.status = self.STATE_ACTIVE

        for profile_name, dict_dns in self.dnss.items():
            dns_obj = dict_dns["DNS_OBJ"]
            update_time = dict_dns["UPDATE_TIME"]
            state = dict_dns["State"]
            if shall_update(force, state, update_time, dns_obj):
                if dns_obj.is_timeout(update_time, time.time()):
                    hs_log("%s DNS timeout, perform updating..." % self.hsName)
                self.perform_dns_update(dict_dns, client_real)

        for profile_name, dict_script in self.scripts.items():
            script_obj = dict_script["SCRIPT_OBJ"]
            update_time = dict_script["UPDATE_TIME"]
            if shall_update(force, self.STATE_UPDATE_OK, update_time, script_obj):
                if script_obj.is_timeout(update_time, time.time()):
                    hs_log("%s Script timeout, perform updating..." % self.hsName)
                self.perform_script_update(dict_script, client_real)

    def perform_dns_update(self, dict_dns, client):
        def real_update():
            result = dns_obj.execute(dns_hostname, client)
            if result:
                dict_dns["UPDATE_TIME"] = time.time()
                dict_dns["State"] = self.STATE_UPDATE_OK
            else:
                dict_dns["State"] = self.STATE_UPDATE_BAD

        dns_obj = dict_dns["DNS_OBJ"]
        dns_hostname = dict_dns["DNS_HOSTNAME"]
        dict_dns["State"] = self.STATE_UPDATE_PENDING

        t = threading.Thread(target=real_update)
        t.setDaemon(True)
        t.start()

    def perform_script_update(self, dict_script, client):
        def real_update():
            result = script_obj.execute(script_param, client)
            if result:
                dict_script["UPDATE_TIME"] = time.time()
                dict_script["State"] = self.STATE_UPDATE_OK
            else:
                dict_script["UPDATE_TIME"] = self.STATE_UPDATE_BAD

        script_obj = dict_script["SCRIPT_OBJ"]
        script_param = dict_script["SCRIPT_PARAM"]
        dict_script["State"] = self.STATE_UPDATE_PENDING

        t = threading.Thread(target=real_update)
        t.setDaemon(True)
        t.start()


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


class Script(_Runner):
    def __init__(self, profile_name, info):
        _Runner.__init__(self)
        self.profile_name = profile_name
        self.commandline = info["command"]
        self.timeout = info["timeout"]

    def execute(self, param, client):
        # TODO: TIMEOUT SHALL BE TAKEN CARE
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
        self.mapFile = filename
        self.threadMapStore = None
        self.checkInterval = self.DEFAULT_CHECK_INTERVAL
        self.checkerTerminateEvent = threading.Event()
        self.checkerTerminateEvent.clear()

        self.open_map_file(self.mapFile)

    def get_config(self):
        return self.mapping["config"]

    def get_host_status(self):
        return {k: v.get_status_all() for k, v in self.hosts.items()}

    def get_host_macs(self, hs_name):
        try:
            host_obj = self.hosts[hs_name]
            return host_obj.validateMac
        except:
            return None

    def open_map_file(self, filename):
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

    def handle_wol_message(self, hs_name):
        def send_wol_message():
            for mac in macs:
                hs_log("WOL: %s" % mac)
                status, output = commands.getstatusoutput("/opt/bin/python /opt/scripts/WOLSender.py %s" % mac)
                if status != 0:
                    hs_log("WOLSender.py failed")
                else:
                    hs_log("WOL Sent")

        if hs_name in self.hosts:
            macs = self.get_host_macs(hs_name)
            t = threading.Thread(target=send_wol_message)
            t.setDaemon(True)
            t.start()
            return macs
        else:
            return None

    def _validate_client(self, client):
        if client.get_hs_name() not in self.hosts:
            return False

        host_obj = self.hosts[client.get_hs_name()]
        return host_obj.validate_client(client)

    def _execute_script_and_nsupdate(self, client):
        if client.get_hs_name() not in self.hosts:
            # TODO: For now if it has entered here, it is a bug.
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
            event_is_set = self.checkerTerminateEvent.wait(self.checkInterval)
            if event_is_set:
                break

            try:
                for hs_name, host in self.hosts.items():
                    host.check_dead()
                    if host.is_online():
                        host.maybe_refresh_dns_and_scripts()
            except:
                hs_log("Unexcepted error at %s %s" % (__file__, sys._getframe().f_lineno))

    def run_updater(self, restart=False):
        if restart:
            if self.threadMapStore is not None:
                hs_log("Trying to restart Updater. Terminating checker...")
                self.checkerTerminateEvent.set()
                self.threadMapStore.join()
                self.threadMapStore = None
                self.checkerTerminateEvent.clear()
                hs_log("Checker terminated, waiting for other threads...")
                # Wait for dns request to finish
                time.sleep(DNS_TIMEOUT + 1)
                self.hosts = {}
                self.dnss = {}
                self.scripts = {}
                self.mapping = {}

                self.open_map_file(self.mapFile)
                hs_log("Restarted.")

        self.run_checker()
