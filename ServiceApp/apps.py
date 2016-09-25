from __future__ import unicode_literals

from django.apps import AppConfig

from TempSensServer.TempSensCoordinator import TempSensCoordinator
from HostService.HostnameServ import HostnameServer, HostnameRequestHandler


class RealApps(object):
    def __init__(self):
        self.tempCoordinator = None
        self.hostServer = None
        self.options = None

    def load_options(self, options):
        self.options = options

    def run_temp_server(self, sensor_port, alarm_port):
        coordinator = TempSensCoordinator(sensor_port=sensor_port, alarm_port=alarm_port)
        coordinator.start_server()
        self.tempCoordinator = coordinator

    def run_hostname_server(self, map_file, hostname_server_port):
        host_server = HostnameServer(map_file, ('', hostname_server_port), HostnameRequestHandler)
        host_server.start_server()
        self.hostServer = host_server

    def run_apps(self):
        self.run_temp_server(self.options.get_sensor_port(), self.options.get_alarm_port())
        self.run_hostname_server(self.options.get_map_file(), self.options.get_hostname_server_port())


class ServiceappConfig(AppConfig):
    name = 'ServiceApp'
    is_ready = False
    
    def __init__(self, *args, **kwargs):
        self.appServerHolder = RealApps()
        AppConfig.__init__(self, *args, **kwargs)

    def ready(self):
        if not self.is_ready:
            print "ready"
            from django.conf import settings
            options = getattr(settings, "SERVICE_APP_CONFIG", "/opt/etc/config.json")
            self.appServerHolder.load_options(options)
            self.appServerHolder.run_apps()
            self.is_ready = True
        else:
            print "Already ready"
