from Utils.AbstractChecker import AbstractChecker
from Utils.TsLog import ts_log


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
