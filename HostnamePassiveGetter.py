import httplib
import json
import threading
import time
import socket
import base64
from Hslog import hs_log
from HostClient import HostClient


class HostnamePassiveGetter(object):
    def __init__(self, mapfile, updater):
        with open(mapfile) as mpf:
            self.config = json.load(mpf)["config"]["PassiveGetter"]
        self.updater = updater
        self.daemonThread = None

    def daemon(self):

        while True:
            try:
                time.sleep(self.config["rpc_query_interval"])
                self.query_for_dead_offline()
            except Exception, e:
                hs_log("unhandled exception %s in passive getter daemon" % str(e))

    def query_for_dead_offline(self):
        host_status = self.updater.get_host_status()
        mac_host_offline = {k: v["mac_address_maybe"]
                            for k, v in host_status.items()
                            if "mac_address_maybe" in v and v["Status"] != "Online"}

        if len(mac_host_offline) == 0:
            return

        try:
            results = json.loads(self.rpc_http_get("/?mac=%s" % ",".join([e[0] for e in mac_host_offline.values()]),
                                                   self.config["rpc_hostname"],
                                                   self.config["rpc_port"], None,
                                                   self.config["rpc_timeout"]))
            for i in range(len(mac_host_offline)):
                result = results["Result"][i]
                if isinstance(result, dict):
                    self.updater.handle_client_heartbeat(
                        HostClient((result.keys()[0], 1234), mac_host_offline.keys()[i], mac=mac_host_offline.values()[i][0])
                    )
        except ValueError:
            hs_log("Cannot parse json result of passive getter rpc")
        except socket.timeout:
            hs_log("rpc timeout of passive getter")
        except socket.gaierror:
            hs_log("cannot resolve name of passive getter server")

    def run_getter(self):
        if self.daemonThread is None:
            self.daemonThread = threading.Thread(target=self.daemon)
            self.daemonThread.setDaemon(True)
            self.daemonThread.start()

    @staticmethod
    def rpc_http_get(path, host=None, port=None, auth=None, timeout=5):
        if port is None:
            port = 80

        if path.startswith("/"):
            path_get = path
            if host is None:
                raise TypeError("host shall be string.")
        else:
            if path[:len("http://")].lower() == "http://":
                path_split = path[len("http://"):].split("/")
            else:
                path_split = path.split("/")
            host_port_url = path_split[0]
            path_get = "/%s" % "/".join(path_split[1:])
            if host is None:
                host_port_split = host_port_url.split(":")
                host = host_port_split[0]
                port = 80 if len(host_port_split) == 1 else int(host_port_split[1])
            elif port is None:
                port = 80

        conn = httplib.HTTPConnection(host, port, timeout=timeout)
        try:
            headers = {}
            if auth is not None:
                headers = {"authorization": "Basic %s" % base64.b64encode("%s:%s" % tuple(auth))}

            conn.request("GET", url=path_get, headers=headers)
        except socket.timeout:
            raise

        res = conn.getresponse()
        res_result = res.read()
        conn.close()
        return res_result

