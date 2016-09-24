from TempAbstractNode import TempAbstractNode


class TempSensNode(TempAbstractNode):
    """
    Node object of temp sensor
    """
    DEFAULT_LOW_RES = (10, 13)
    DEFAULT_HIGH_RES = (27, 32)
    # DEFAULT_LOW_RES = (0, 3)
    # DEFAULT_HIGH_RES = (7, 12)

    def __init__(self, temp_thres_low=None, temp_thres_high=None, *args, **kwargs):
        self.temperature = -273
        self.alarm = False
        if temp_thres_low is None or not isinstance(temp_thres_low, tuple):
            temp_thres_low = self.DEFAULT_LOW_RES

        if temp_thres_high is None or not isinstance(temp_thres_high, tuple):
            temp_thres_high = self.DEFAULT_HIGH_RES

        self.thres_low = temp_thres_low
        self.thres_high = temp_thres_high

        TempAbstractNode.__init__(self, *args, **kwargs)

    @staticmethod
    def get_node_type():
        return "Temp Sensor Node"

    def update(self, temperature, *args, **kwargs):
        if self.alarm:
            if self.temperature < self.thres_low[1] < temperature:
                self.alarm = False
            elif self.temperature > self.thres_high[0] > temperature:
                self.alarm = False
            else:
                pass
        else:
            if self.thres_low[0] > temperature:
                self.alarm = True
            elif self.thres_high[1] < temperature:
                self.alarm = True
            else:
                pass

        self.temperature = temperature
        TempAbstractNode.update(self, *args, **kwargs)

    def get_temperature(self):
        return self.temperature

    def shall_alarm(self):
        return self.alarm

    def get_node_info(self):
        info = TempAbstractNode.get_node_info(self)
        info["lastTemperature"] = self.get_temperature()
        info["lowThreshold"] = list(self.thres_low)
        info["highThreshold"] = list(self.thres_high)
        return info


