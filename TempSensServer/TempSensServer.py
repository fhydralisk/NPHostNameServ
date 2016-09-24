import struct

from TempAbstractServer import TempAbstractServer
from TempSensNode import TempSensNode
import MiscFunc


class TempSensServer(TempAbstractServer):
    """
    Server object for temp sensor
    """

    def __init__(self, coordinator, host=None, port=8124, version=0x0100):
        if host is None:
            host = ''
        TempAbstractServer.__init__(self, coordinator, host, port, version)

    @staticmethod
    def new_node(info, address):
        return TempSensNode(device_id=info["devid"], version=info["ver"])

    def parse_message_info(self, message):
        temp_raw = MiscFunc.get_short_from_buf(message[4:6])
        temp = self.process_temp(temp_raw)
        common_info = TempAbstractServer.parse_message_info(self, message)
        common_info["temp"] = temp
        return common_info

    def update_node(self, node, info, address):
        node.update(temperature=info["temp"], address=address)

    def do_reply(self, key, node, info, address):
        return self.heartbeat(key)

    @staticmethod
    def process_temp(t):
        if t & 0x800:
            t = - (t & 0x7FF)

        return t * 0.0625

    @staticmethod
    def heartbeat(devid):
        return struct.pack("!2BH", 0x0f, 0xf0, devid)

    def shall_alarm(self, devid):
        try:
            return self.nodeDict[devid].shall_alarm()
        except KeyError:
            raise

    @staticmethod
    def server_type():
        return "Sensor Server"
