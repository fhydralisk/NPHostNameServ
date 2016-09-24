import os
import sys


class Daemonizer(object):
    def __init__(self, daemon=True, stdout=None, stderr=None):
        self.runDaemon = daemon
        self.stdout = stdout if stdout is not None else '/dev/null'
        self.stderr = stderr if stderr is not None else '/dev/null'

    def start_process(self):
        if self.runDaemon:
            self.daemon()
        self.process()

    def daemon(self):
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
        so = file(self.stdout, 'a+')
        serr = file(self.stderr, 'a+')
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(serr.fileno(), sys.stderr.fileno())

    def process(self):
        pass

    def daemonlize(self):
        self.daemon()
