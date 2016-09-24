import struct

from TempAbstractServer import TempAbstractServer
from TempAlarmNode import TempAlarmNode
import MiscFunc


class TempAlarmServer(TempAbstractServer):
    """
    Server object for temp sensor
    """
    CMD_QUERY_RESULT = 0x01
    CMD_SET_TARGETID = 0x02
    CMD_SET_WIFI = 0x03
    CMD_SET_HOST = 0x04

    PAYLOAD_ALARM = '\x70'
    PAYLOAD_NOALARM = '\x07'

    def __init__(self, coordinator, host=None, port=8125, version=0x0100):
        if host is None:
            host = ''
        TempAbstractServer.__init__(self, coordinator, host, port, version)

    @staticmethod
    def new_node(info, address):
        return TempAlarmNode(device_id=info["devid"], version=info["ver"], target_id=info["targetid"])

    def parse_message_info(self, message):
        target_id = MiscFunc.get_short_from_buf(message[4:6])
        common_info = TempAbstractServer.parse_message_info(self, message)
        common_info["targetid"] = target_id
        return common_info

    def update_node(self, node, info, address):
        node.update(target_id=info["targetid"], address=address)

    def do_reply(self, key, node, info, address):
        return self.send_shall_alarm(info["targetid"])

    def send_shall_alarm(self, devid):
        shall_alarm = self.coordinator.shall_alarm(devid)
        if shall_alarm is None:
            return None
        elif shall_alarm:
            payload = self.PAYLOAD_ALARM
        else:
            payload = self.PAYLOAD_NOALARM

        return self.build_reply(self.version, self.CMD_QUERY_RESULT, payload)

    @staticmethod
    def build_reply(version, cmd, payload):
        reply = struct.pack("!2BHBB%ds" % len(payload), 0x0F, 0xF0, version, cmd, len(payload), payload)
        reply += struct.pack("B", MiscFunc.calc_crc(reply[2:]))
        return reply

    @staticmethod
    def server_type():
        return "Alarm Server"
