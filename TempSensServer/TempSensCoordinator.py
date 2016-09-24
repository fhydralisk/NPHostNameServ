from TempAlarmServer import TempAlarmServer
from TempSensServer import TempSensServer
from NodeStateChecker import NodeStateChecker
from TsLog import ts_log


class TempSensCoordinator(object):
    """
    Coordinator of Server
    """
    def __init__(self, sensor_port, alarm_port):
        self.sensServer = TempSensServer(coordinator=self, port=sensor_port)
        self.alarmServer = TempAlarmServer(coordinator=self, port=alarm_port)
        self.checker = NodeStateChecker()

    def start_server(self):
        try:
            if not self.sensServer.is_running():
                self.sensServer.run_deamon()
            if not self.alarmServer.is_running():
                self.alarmServer.run_deamon()
            self.checker.register(self.sensServer.server_type(), self.sensServer.nodeDict)
            self.checker.register(self.alarmServer.server_type(), self.alarmServer.nodeDict)
            self.checker.run_checker()

        except:
            ts_log("Error when starting server.")
            exit(1)

    def shall_alarm(self, devid):
        try:
            return self.sensServer.shall_alarm(devid)
        except KeyError:
            return None
        except:
            ts_log("Unexpected error happen in shall_alarm", debug_trace=True)
            return None

    def get_nodes_info(self):
        return {
            self.sensServer.server_type(): self.sensServer.get_nodes_info(),
            self.alarmServer.server_type(): self.alarmServer.get_nodes_info(),
        }

    def get_auth(self):
        return {
            "username": "fiblab",
            "password": "fib10202",
        }


