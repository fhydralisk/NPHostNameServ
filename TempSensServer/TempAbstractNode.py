import time
import MiscFunc


class TempAbstractNode(object):
    """
    Abstract class of sensor nodes.
    """

    def __init__(self, version, device_id, timeout=30, remove_when_dead=True):
        self.version = version
        self.deviceId = device_id
        self.timeout = timeout
        self.lastAction = time.time()
        self.lastAddress = None
        self.autoRemove = remove_when_dead

    def is_alive(self):
        if time.time() - self.lastAction > self.timeout:
            return False
        return True

    def remove_when_dead(self):
        return self.autoRemove

    @staticmethod
    def get_node_type():
        return "Abstract Node"

    def get_nid(self):
        return self.deviceId

    def get_version(self):
        return self.version

    def update(self, address, *args, **kwargs):
        self.lastAddress = address
        self.lastAction = time.time()

    def get_node_info(self):
        return {
            "version": self.version,
            "deviceId": self.deviceId,
            "lastSeen": MiscFunc.format_timestamp(self.lastAction),
            "lastAddress": self.lastAddress[0],
        }

