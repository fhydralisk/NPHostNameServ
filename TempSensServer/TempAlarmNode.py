from TempAbstractNode import TempAbstractNode


class TempAlarmNode(TempAbstractNode):
    """
    Node object of temp sensor
    """

    def __init__(self, target_id=0, *args, **kwargs):
        self.targetId = target_id
        TempAbstractNode.__init__(self, *args, **kwargs)

    @staticmethod
    def get_node_type():
        return "Temp Alarm Node"

    def update(self, target_id, *args, **kwargs):
        self.targetId = target_id
        TempAbstractNode.update(self, *args, **kwargs)

    def get_target_id(self):
        return self.targetId

    def set_target_id(self, target_id):
        self.targetId = target_id

    def get_node_info(self):
        info = TempAbstractNode.get_node_info(self)
        info["target_id"] = self.targetId
        return info
