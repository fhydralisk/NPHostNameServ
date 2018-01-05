import os, sys, json
from FIBConnector import FIBConnector
from HostnameUpdater import HostnameUpdater
from HostnamePassiveGetter import HostnamePassiveGetter
from HostnameServ import HostnameServer, HostnameRequestHandler
from utils import hs_log


def print_usage():
    print "Usage:"
    print "RunUpdater.py ConfigFile Daemon"


def daemon():
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

configFile = sys.argv[1]

with open(configFile) as cf:
    c_entire = json.load(cf)
    passive_getter_config = c_entire["PassiveGetter"]
    ddns_connector_config = c_entire["DDNSServer"]
    updater_config = c_entire["Updater"]
    config = c_entire["config"]

if len(sys.argv) == 3:
    daemonlize = sys.argv[2]
else:
    daemonlize = config["Daemon"]

if daemonlize.upper() == "TRUE" or daemonlize.upper() == "YES" or daemonlize == "1":
    daemon()

connector = FIBConnector(ddns_connector_config)
updater = HostnameUpdater(updater_config, connector)
updater.run_updater(restart=False)
passiveGetter = HostnamePassiveGetter(passive_getter_config, updater)
passiveGetter.run_getter()
hostServer = HostnameServer(updater, ('', config["port"]), HostnameRequestHandler)
hs_log("Starting HostnameServer...")
try:
    hostServer.serve_forever()
except:
    hs_log("HostnameServ deamon unexceptly stopped.")
    sys.exit(3)
