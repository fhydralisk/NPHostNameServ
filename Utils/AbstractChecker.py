import threading


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

    def stop_checker(self, wait=False):
        if self.deamonThread is None:
            return

        self.checkerTerminateEvent.set()
        if wait:
            self.deamonThread.join()

    def on_terminate(self):
        self.deamonThread = None
        self.checkerTerminateEvent.clear()

    def is_running(self):
        if self.deamonThread is None:
            return False

        return self.deamonThread.isAlive()

    def check(self):
        pass
