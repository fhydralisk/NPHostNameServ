import socket
import threading
import time

import MiscFunc
from TsLog import ts_log


class AbstractServer(object):
    """
    Abstract server class
    """
    DEFAULT_SOCKET_TIMEOUT = 5

    def __init__(self, host, port, version):
        self.socket = None
        self.host = host
        self.port = port
        self.version = version
        self.serverThread = None
        self.deamonRun = False

    def run_deamon(self):
        retry = 0
        max_attempt = 5
        while retry < max_attempt:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.socket.bind((self.host, self.port))
                self.socket.settimeout(self.DEFAULT_SOCKET_TIMEOUT)
            except socket.error:
                ts_log("Cannot bind to %s:%d" % (self.host, self.port))
                if retry < max_attempt:
                    retry += 1
                    time.sleep(5)
                    continue
                else:
                    ts_log("Cannot start server after %d retries" % max_attempt)
                    raise
            else:
                self.deamonRun = True
                self.serverThread = threading.Thread(target=self.deamon)
                self.serverThread.setDaemon(True)
                self.serverThread.start()
                break

    def stop_deamon(self):
        if not self.deamonRun:
            return

        self.deamonRun = False
        self.serverThread.join(self.DEFAULT_SOCKET_TIMEOUT * 2)
        self.serverThread = None

        try:
            self.socket.close()
            self.socket = None
        except:
            pass

    def deamon(self):
        while self.deamonRun:
            try:
                data, addr = self.socket.recvfrom(1024)
            except socket.timeout:
                pass
            except Exception, e:
                self.serverThread = None
                break
            else:
                self.handle_message(data, addr)

        self.serverThread = None
        ts_log("Deamon thread of %s exit" % str(self.__class__))

    def handle_message(self, message, address):
        raise Exception("Not Implemented")

    def send_message(self, message, address):
        self.socket.sendto(message, address)

    def is_running(self):
        return self.deamonRun


class TempAbstractServer(AbstractServer):
    """
    Abstract server class of Temp Sens Net
    """
    def __init__(self, coordinator, host=None, port=10000, version=0x0100):
        if host is None:
            host = ''
        self.coordinator = coordinator
        self.nodeDict = {}
        AbstractServer.__init__(self, host, port, version)

    def handle_message(self, message, address):
        try:
            key = self.get_key_from_message(message)
            info = self.parse_message_info(message)
            if key not in self.nodeDict:
                self.nodeDict[key] = self.new_node(info, address)

            self.update_node(self.nodeDict[key], info, address)
            reply = self.do_reply(key, self.nodeDict[key], info, address)
            if reply is not None:
                self.send_message(reply, address)
        except Exception, e:
            ts_log("Error when handling message, error:%s " % str(e), debug_trace=True)

    @staticmethod
    def get_key_from_message(message):
        """
        Get Key of node dict from message.
        Commonly Devid filed.
        :param message: packet
        :return: key to store in dict
        """

        try:
            return MiscFunc.get_short_from_buf(message[2:4])
        except:
            return None

    @staticmethod
    def get_version_from_message(message):
        try:
            return MiscFunc.get_short_from_buf(message[0:2])
        except:
            return None

    @staticmethod
    def new_node(info, address):
        raise RuntimeError("Not Implemented")

    def update_node(self, node, info, address):
        raise RuntimeError("Not Implemented")

    def do_reply(self, key, node, info, address):
        return None

    def parse_message_info(self, message):
        version = self.get_version_from_message(message)
        devid = self.get_key_from_message(message)

        return {
            "ver": version,
            "devid": devid,
        }

    def get_nodes_info(self):
        info_dict = {str(n): v.get_node_info() for n, v in self.nodeDict.items()}
        return info_dict

    @staticmethod
    def server_type():
        return "Abstract Server"


