from Utils.AbstractChecker import AbstractChecker
from Utils.Hslog import hs_log


class HostChecker(AbstractChecker):
    def __init__(self, hosts, *args, **kwargs):
        self.hosts = hosts
        AbstractChecker.__init__(self, *args, **kwargs)

    def set_hosts(self, hosts):
        self.hosts = hosts

    def check(self):
        try:
            for hs_name, host in self.hosts.items():
                host.check_dead()
                if host.is_online():
                    host.maybe_refresh_dns_and_scripts()
        except:
            hs_log("Unexcepted error at %s %s" % (__file__, sys._getframe().f_lineno))

    def on_terminate(self):
        hs_log("Host Checker thread is dead")
        AbstractChecker.on_terminate(self)
