import commands


class _Runner(object):
    def __init__(self):
        self.timeout = 0

    @staticmethod
    def replace_fields(text, host=None, ipaddr=None, username=None, password=None):
        ret = text

        ret = ret.replace("%host", host) if host is not None else ret
        ret = ret.replace("%ipaddr", ipaddr) if ipaddr is not None else ret
        ret = ret.replace("%username", username) if username is not None else ret
        ret = ret.replace("%password", password) if password is not None else ret

        return ret

    def execute(self, param, client):
        raise Exception("Not Implemented")

    def is_timeout(self, time_last, time_now):
        if self.timeout == 0:
            return False
        return time_now - time_last > self.timeout
