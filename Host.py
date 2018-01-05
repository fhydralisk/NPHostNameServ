import time
from utils import format_timestamp, hs_log


class Host(object):
    STATE_ACTIVE = "Online"
    STATE_DEAD = "Dead"
    STATE_OFFLINE = "Offline"
    STATE_UPDATE_NONE = "N/A"
    STATE_UPDATE_PENDING = "Updating"
    STATE_UPDATE_OK = "OK"
    STATE_UPDATE_BAD = "Bad"
    DEFAULT_DEAD_INTERVAL = 900

    def __init__(self, name, validate=None, dead_interval=None, is_proactive=True):
        self.name = name
        self.status = self.STATE_OFFLINE
        self.is_proactive = is_proactive
        self.update_state = self.STATE_UPDATE_NONE
        self.last_ns_update = 0
        self.last_try_ns_update = 0
        self.update_bad_reason = ""
        self.lastUpdate = 0
        self.lastIp = "0.0.0.0"
        self.lastClient = None
        self.validateMac = None
        self.deadInterval = dead_interval if isinstance(dead_interval, int) else self.DEFAULT_DEAD_INTERVAL

        if validate is not None:
            # TODO: Validate
            self.validateMac = [validate]

    def set_online(self):
        self.set_state(self.STATE_ACTIVE)

    def set_offline(self):
        self.set_state(self.STATE_OFFLINE)

    def set_dead(self):
        self.set_state(self.STATE_DEAD)

    def set_state(self, state):
        if state not in [self.STATE_ACTIVE, self.STATE_DEAD, self.STATE_OFFLINE]:
            raise ValueError

        self.status = state

    def get_status_all(self, format_time=True):
        ret = {
            "Status": self.status,
            "DNS_Status": self.update_state,
            "Last_IP": self.lastIp,
            "is_proactive": self.is_proactive,
            "Last_update": format_timestamp(self.lastUpdate) if format_time else self.lastUpdate,
        }

        if self.lastClient is not None:
            ret["last_address"] =\
                {k: v for k, v in self.lastClient.get_address().items() if k != "port" and v is not None}
        if self.validateMac is not None:
            ret["mac_address_maybe"] = self.validateMac

        return ret

    def check_dead(self):
        if self.is_online():
            if time.time() - self.lastUpdate > self.deadInterval:
                self.status = self.STATE_DEAD
                hs_log("%s is dying." % self.name)

    def is_online(self):
        return self.status in [self.STATE_ACTIVE]

    def validate_client(self, client):
        if self.validateMac is not None:
            client_mac = client.get_address()["mac"]
            if client_mac is None or client_mac not in self.validateMac:
                return False

        return True

    def update(self, client):
        """
        update a host's info.
        :param client: The last client.
        :return: If ip is updated, return True, otherwise False.
        """
        new_ip = client.client.get_address()["ip"]
        self.lastClient = client
        self.lastUpdate = time.time()
        if self.lastIp != new_ip:
            self.lastIp = new_ip
            return True

        return False

    def ns_setstate_try_update(self):
        self.update_state = Host.STATE_UPDATE_PENDING
        self.last_try_ns_update = time.time()

    def ns_setstate_updated(self):
        self.update_state = Host.STATE_UPDATE_OK
        self.last_ns_update = time.time()
        self.update_bad_reason = ""

    def ns_setstate_bad_update(self, reason):
        self.update_state = Host.STATE_UPDATE_BAD
        self.update_bad_reason = reason

    def should_update_ns(self, good_refresh_interval, bad_retry_interval, pending_retry_interval):
        """
        This function determines whether a host should refresh
        when a bad one shall be update
        2.2) when a good one shall be update
        :param good_refresh_interval: the interval of refresh
        :param bad_retry_interval: the interval of retry if update failed
        :param pending_retry_interval: the interval of retry if stay pending
        :return: True if shall update, otherwise false
        """
        if self.update_state == Host.STATE_UPDATE_OK and time.time() - self.last_ns_update > good_refresh_interval:
            return True

        if self.update_state == Host.STATE_UPDATE_BAD and time.time() - self.last_ns_update > bad_retry_interval:
            return True

        if self.update_state == Host.STATE_UPDATE_PENDING and time.time() - self.last_try_ns_update > pending_retry_interval:
            # Pending state too long, not expected.
            return True

        return False
