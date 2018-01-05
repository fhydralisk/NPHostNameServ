import httplib
import json
import threading
import time
import socket
import base64
from utils import hs_log
from HostClient import HostClient


class HostnamePassiveGetter(object):
    def __init__(self, config, updater):
        self.config = config
        self.updater = updater
        self.daemonThread = None

    def _daemon(self):
        while True:
            try:
                self.get_passive_ips()
            except Exception, e:
                hs_log("unhandled exception %s in passive getter daemon" % str(e))

            time.sleep(self.config["rpc_query_interval"])

    def get_passive_ips(self):
        passive_clients = self.updater.get_all_passive_clients()
        macs = [client.validateMac[0] for client in passive_clients]

        try:
            results = json.loads(self.rpc_http_get("/?mac=%s" % ",".join(macs),
                                                   self.config["rpc_hostname"],
                                                   self.config["rpc_port"], None,
                                                   self.config["rpc_timeout"]))

            ips = results["Result"]
            for client, ip_ts in zip(passive_clients, ips):
                if isinstance(ip_ts, dict):
                    self.updater.handle_client_heartbeat(
                        HostClient((ip_ts.keys()[0], 1234), client.name, mac=client.validateMac[0]),
                        is_proactive=False
                    )
        except ValueError:
            hs_log("Cannot parse json result of passive getter rpc")
        except socket.timeout:
            hs_log("rpc timeout of passive getter")
        except socket.gaierror:
            hs_log("cannot resolve name of passive getter server")

    def run_getter(self):
        if self.daemonThread is None:
            self.daemonThread = threading.Thread(target=self._daemon)
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

