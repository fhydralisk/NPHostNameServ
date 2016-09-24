import threading

from TsLog import ts_log


class AbstractChecker(object):
    """
    Checker deamon
    """

    def __init__(self, step_time=5):
        self.checkInterval = step_time
        self.deamonThread = None
        self.checkerTerminateEvent = threading.Event()
        self.checkerTerminateEvent.clear()

    def deamon(self):
        try:
            while True:
                event_is_set = self.checkerTerminateEvent.wait(self.checkInterval)
                if event_is_set:
                    break
                self.check()
        finally:
            self.on_terminate()

    def run_checker(self):
        if self.deamonThread is None:
            self.checkerTerminateEvent.clear()
            self.deamonThread = threading.Thread(target=self.deamon)
            self.deamonThread.setDaemon(True)
            self.deamonThread.start()
        else:
            raise RuntimeError("Deamon is already running")

    def stop_checker(self):
        if self.deamonThread is None:
            return

        self.checkerTerminateEvent.set()

    def on_terminate(self):
        self.deamonThread = None
        self.checkerTerminateEvent.clear()

    def check(self):
        pass


class NodeStateChecker(AbstractChecker):
    """
    Node Checker
    """
    def __init__(self, *args, **kwargs):
        self.checkList = {}
        AbstractChecker.__init__(self, *args, **kwargs)

    def register(self, server_type, dict_of_node):
        self.checkList[server_type] = dict_of_node

    def unregister(self, dict_of_node):
        if dict_of_node in self.checkList:
            del self.checkList[dict_of_node]

    def check(self):
        for node_dict in self.checkList.values():
            for nid, node in node_dict.items():
                if not node.is_alive() and node.remove_when_dead():
                    del node_dict[nid]
                    ts_log("Node of type %s, id=%d is dead" % (node.get_node_type(), nid))

    def on_terminate(self):
        ts_log("Checker thread is dead")
        AbstractChecker.on_terminate(self)
