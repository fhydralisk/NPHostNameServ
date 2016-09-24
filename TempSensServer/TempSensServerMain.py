import sys
import os
from TempSensCoordinator import TempSensCoordinator
from TsLog import ts_log
from ReportInterface import TempSensWebServer, TempSensRequestHandler


def print_usage():
    print "Usage: TempSensServerMain.py sensor_port alarm_port web_port deamon"


def run_server(sensor_port, alarm_port, web_port):
    coordinator = TempSensCoordinator(sensor_port=sensor_port, alarm_port=alarm_port)
    coordinator.start_server()
    host_server = TempSensWebServer(coordinator, ('', web_port), TempSensRequestHandler)

    ts_log("Starting TempSensServer...")
    try:
        host_server.serve_forever()
    except:
        ts_log("TempSensServer deamon unexceptly stopped.")
    sys.exit(3)


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

_sensor_port = 8124
_alarm_port = 8125
_web_port = 8126

try:
    _sensor_port = int(sys.argv[1])
    _alarm_port = int(sys.argv[2])
    _web_port = int(sys.argv[3])
except:
    ts_log("startup failed ")
    print_usage()
    exit(1)

if sys.argv[4].upper() not in ["YES","TRUE", "NO", "FALSE"]:
    print_usage()
    exit(1)
elif sys.argv[4].upper() in ["YES", "TRUE"]:
    deamon()

run_server(_sensor_port, _alarm_port, _web_port)
