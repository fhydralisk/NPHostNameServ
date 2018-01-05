from Runner import _Runner
import commands
from utils import hs_log


class Script(_Runner):
    def __init__(self, profile_name, info):
        _Runner.__init__(self)
        self.profile_name = profile_name
        self.commandline = info["command"]
        self.timeout = info["timeout"]

    def execute(self, param, client):
        # TODO: TIMEOUT SHALL BE TAKEN CARE
        commandline_real = self.commandline + " " + self.replace_fields(param, ipaddr=client.get_address()["ip"])
        status, output = commands.getstatusoutput(commandline_real)
        hs_log("Script %s run, statue=%d, output=%s" % (commandline_real, status, output))
        return status == 0
