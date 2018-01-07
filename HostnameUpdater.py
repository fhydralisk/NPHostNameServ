import threading, time
from utils import hs_log
from Host import Host


class HostnameUpdater(object):
    DEFAULT_CHECK_INTERVAL = 5

    def __init__(self, config, connector):
        self.config = config
        self.connector = connector
        self.hosts = {}
        self.clients = {}
        self.threadMapStore = None
        self.threadPerformUpdate = None
        self.checkInterval = self.DEFAULT_CHECK_INTERVAL
        self.checkerTerminateEvent = threading.Event()
        self.checkerTerminateEvent.clear()
        self.dnsUpdateEvent = threading.Event()
        self.dnsUpdateEvent.clear()
        self._fetch_clients()
        self._cache_update = []
        self._cache_update_lock = threading.Lock()
        # if the serial changes, it indicates the client db is changed and shall be updated.
        self.serial = 0
        self.last_serial_check = 0
        self.serialUpdateEvent = threading.Event()
        self.serialUpdateEvent.clear()

    def _fetch_clients(self):
        resp = self.connector.get_clients()
        if resp is None or resp["Result"] != "OK":
            return

        self.serial = resp["serial"]
        self.last_serial_check = time.time()

        self.clients = resp["clients"]
        # Update host map(Append)
        for clientname, clientconfig in self.clients.items():
            if clientname not in self.hosts:
                # Append Host
                try:
                    if ("MAC" not in clientconfig or len(clientconfig["MAC"]) < 7) and not clientconfig["is_proactive"]:
                        # Exclude idiot clients.
                        continue

                    self.hosts[clientname] = Host(
                        clientname,
                        clientconfig["MAC"] if "MAC" in clientconfig else None,
                        self.config["DEAD_INTERVAL"],
                        clientconfig["is_proactive"]
                    )
                except KeyError:
                    hs_log("Key error in client config " + str(clientconfig))

        # Update host map(Remove)
        hosts_to_remove = []
        for host in self.hosts:
            if host not in self.clients:
                hosts_to_remove.append(host)

        for host_rm in hosts_to_remove:
            del self.hosts[host_rm]

    def _check_serial(self):
        resp = self.connector.get_serial()
        if resp is not None and resp["Result"] == "OK":
            self.last_serial_check = time.time()
            if resp["serial"] != self.serial:
                # perform host update
                self._fetch_clients()
                self.serialUpdateEvent.set()

    def _put_into_update_queue(self, host):
        self._cache_update_lock.acquire()
        try:
            if host not in self._cache_update:
                self._cache_update.append(host)
                hs_log("Host %s has been put into updating queue." % host.name)
        except Exception, e:
            hs_log("Uncaught exception " + str(e) + " when queueing update host")
        finally:
            self._cache_update_lock.release()

    def _get_all_from_update_queue(self):
        self._cache_update_lock.acquire()
        ret = self._cache_update
        self._cache_update = []
        self._cache_update_lock.release()
        return ret

    def _thread_perform_update(self):
        """
        This thread performs dns update tasks.
        :return: None
        """
        while True:
            self.dnsUpdateEvent.wait(self.config["DNS_BATCH_UPDATE_INTERVAL"])
            update_hosts = self._get_all_from_update_queue()
            if len(update_hosts) > 0:
                # performs unzip to build names and ips from hosts
                names, ips = zip(*[(host.name, host.lastIp) for host in update_hosts])
                name_to_host = {host.name: host for host in update_hosts}

                # Prevent empty updating
                if len(names) > 0:
                    for host in update_hosts:
                        host.ns_setstate_try_update()

                    try:
                        update_results = self.connector.update_dns(names, ips)
                        if update_results is not None and "Result" in update_results and update_results["Result"] == "OK":
                            # Update DNS Update state for these nodes.
                            for name, result in update_results["Result Map"].items():
                                if result == "OK":
                                    name_to_host[name].ns_setstate_updated()
                                else:
                                    name_to_host[name].ns_setstate_bad_update(result)
                        else:
                            # Failed to update
                            for host in update_hosts:
                                host.ns_setstate_bad_update("Error when receiving result of rpc.")

                    except Exception, e:
                        for host in update_hosts:
                            host.ns_setstate_bad_update("Unexpected exception" + str(e))
                        hs_log("Unexpected exception " + str(e) + " occurred in DNS perform update thread.")

    def _thread_host_checker(self):
        """
        This thread checks:
        1) whether a host should be marked as Down;
        2) whether a host should be re-updated;
        3) check serial to determine if the host shall be reloaded.
        :return: None
        """
        # If a host is marked as failed being updated, should try reupdate it;
        # if a host is not being updated for a while, reupdate it.
        while True:
            event_is_set = self.checkerTerminateEvent.wait(self.checkInterval)
            if event_is_set:
                break

            try:
                # Check DNS and State
                for hs_name, host in self.hosts.items():
                    host.check_dead()
                    if host.should_update_ns(
                        self.config["GOOD_REFRESH_INTERVAL"],
                        self.config["BAD_RETRY_INTERVAL"],
                        self.config["PENDING_RETRY_INTERVAL"]
                    ):
                        self._put_into_update_queue(host)

                # Check serial
                if time.time() - self.last_serial_check > self.config["SERIAL_CHECK_INTERVAL"]:
                    self._check_serial()

            except Exception, e:
                hs_log("Unexpected exception " + str(e) + " occurred in host checker.")

    def get_host_status(self):
        return {k: v.get_status_all() for k, v in self.hosts.items()}

    def get_host_macs(self, hs_name):
        try:
            host_obj = self.hosts[hs_name]
            return host_obj.validateMac
        except:
            return None

    def handle_client_heartbeat(self, client, is_proactive=True):
        if self._validate_client(client):
            self._update_host(client, is_proactive)
        else:
            raise EnvironmentError

    def _validate_client(self, client):
        if client.get_hs_name() not in self.hosts:
            return False

        host_obj = self.hosts[client.get_hs_name()]
        return host_obj.validate_client(client)

    def _update_host(self, client, is_proactive):
        if client.get_hs_name() not in self.hosts:
            # TODO: For now if it has entered here, it is a bug.
            return False

        if self.hosts[client.get_hs_name()].is_proactive != is_proactive:
            return False

        if self.hosts[client.get_hs_name()].update(client):
            # pull this host into update queue
            self._put_into_update_queue(self.hosts[client.get_hs_name()])
        return True

    def run_checker(self):
        if self.threadMapStore is None:
            self.threadMapStore = threading.Thread(target=self._thread_host_checker)
            self.threadMapStore.setDaemon(True)
            self.threadMapStore.start()

    def run_dns_updater(self):
        if self.threadPerformUpdate is None:
            self.threadPerformUpdate = threading.Thread(target=self._thread_perform_update)
            self.threadPerformUpdate.setDaemon(True)
            self.threadPerformUpdate.start()

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
                time.sleep(5)
                self.hosts = {}
                hs_log("Restarted.")

        self.run_checker()
        self.run_dns_updater()

    def get_all_passive_clients(self):
        return [host for host in self.hosts.values() if not host.is_proactive]

    def get_all_proactive_clients(self):
        return [host for host in self.hosts.values() if host.is_proactive]
