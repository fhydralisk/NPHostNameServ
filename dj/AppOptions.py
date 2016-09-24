from TempSensServer.TempSensCoordinator import TempSensCoordinator
from HostService.HostnameServ import HostnameServer, HostnameRequestHandler
import json
from Utils.Hslog import hs_log


class AppOptions(object):
    def __init__(self, config_file):
        try:
            f = open(config_file)
            self.option = json.load(f)
            f.close()
        except IOError:
            hs_log("Configuration file not found.")
            raise
        except ValueError:
            hs_log("Bad format of configration file.")
            raise

    def get_sensor_port(self, default=8124):
        try:
            return self.option["TemperatureServer"]["Sensor"]["Socket"]["port"]
        except KeyError:
            return default

    def get_sensor_host(self, default=''):
        try:
            return self.option["TemperatureServer"]["Sensor"]["Socket"]["host"]
        except KeyError:
            return default

    def get_alarm_port(self, default=8125):
        try:
            return self.option["TemperatureServer"]["Alarm"]["Socket"]["port"]
        except KeyError:
            return default

    def get_alarm_host(self, default=''):
        try:
            return self.option["TemperatureServer"]["Alarm"]["Socket"]["host"]
        except KeyError:
            return default

    def get_hostname_server_port(self, default=8123):
        try:
            return self.option["HostnameServer"]["Socket"]["port"]
        except KeyError:
            return default

    def get_hostname_server_host(self, default=''):
        try:
            return self.option["HostnameServer"]["Socket"]["host"]
        except KeyError:
            return default

    def get_map_file(self, default='/opt/etc/Hostnames.json'):
        try:
            return self.option["HostnameServer"]["MapFile"]
        except KeyError:
            return default

    def get_ui_server_host(self, default=''):
        try:
            return self.option["WebUI"]["Socket"]["host"]
        except KeyError:
            return default

    def get_ui_server_port(self, default=9000):
        try:
            return self.option["WebUI"]["Socket"]["port"]
        except KeyError:
            return default

    def get_daemon(self, default=False):
        try:
            return self.option["General"]["Daemon"]
        except KeyError:
            return default
