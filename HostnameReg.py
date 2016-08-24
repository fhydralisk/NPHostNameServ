import os, sys, time, httplib


def print_usage():
    print "Usage:"
    print "HostnameReg.py name hs_remotehost reportInterval deamon"


class HostRegMachine(object):

    def __init__(self, r_name, r_host, interval):
        self.r_name = r_name
        host, port = r_host.split(':')
        port = int(port)
        self.r_host = host
        self.r_port = port
        self.interval = interval
        self.initial_interval = 1

    def update_ns(self):
        conn = httplib.HTTPConnection(self.r_host, self.r_port, timeout=11)
        try:
            conn.request('GET', '/?name=%s' % self.r_name)
            res = conn.getresponse()
            conn.close()
            if res.status == 200:
                return True
            else:
                return False
        except:
            return False

    def reg_scheduler(self):

        next_interval = self.initial_interval
        while True:
            status = self.update_ns()
            # status, output = \
            #    commands.getstatusoutput('%s -T11 --tries=1 -O /dev/null "http://%s/?name=%s"' %
            #                              (self.path_wget, self.r_host, self.r_name))

            if not status:
                if next_interval > self.interval / 2:
                    next_interval = self.initial_interval
                elif next_interval * 2 < self.interval / 2:
                    next_interval *= 2
                else:
                    next_interval = self.interval / 2

            else:
                next_interval = self.interval
                pass

            time.sleep(next_interval)




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

if len(sys.argv) != 5:
    print_usage()
    exit(1)

regName = sys.argv[1]
regHost = sys.argv[2]
normInterval = int(sys.argv[3])
deamonlize = sys.argv[4]

if deamonlize.upper() == "TRUE" or deamonlize.upper() == "YES" or deamonlize == "1":
    deamon()

# reg_scheduler(regName, regHost, normInterval, pathWget)
hostRegMachine = HostRegMachine(regName, regHost, normInterval)
hostRegMachine.reg_scheduler()
