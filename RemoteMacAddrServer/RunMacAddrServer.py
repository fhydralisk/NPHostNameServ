import os, sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from RemoteMacAddrServer import RemoteMacAddrServer, RemoteMacAddrHandler
from utils import hs_log


def print_usage():
    print "Usage:"
    print "RunMacAddrServer.py Port Daemon"


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


if len(sys.argv) != 3:
    print_usage()
    exit(1)

port = int(sys.argv[1])
daemonlize = sys.argv[2]

if daemonlize.upper() == "TRUE" or daemonlize.upper() == "YES" or daemonlize == "1":
    daemon()

hostServer = RemoteMacAddrServer(
    None,
    ('', port),
    RemoteMacAddrHandler
)
hs_log("Starting MacAddrServer...")

try:
    hostServer.serve_forever()
except Exception, e:
    hs_log("Server unexceptly stopped. " + str(e))
    sys.exit(3)
