import time
import traceback, commands

loggerPath = "/usr/bin/logger"


def hs_log(msg, tag="HostnameServ", debug_print=False, debug_trace=True):

    if debug_print:
        print msg
        try:
            traceback.print_exc()
        except ValueError:
            pass

    if isinstance(tag, basestring):
        tag = " -t " + tag
    else:
        tag = ""

    if debug_trace:
        msg = msg + "traceback:" + traceback.format_exc()

    msg = msg.replace('"', r'\"')
    commands.getstatusoutput(loggerPath + " " + tag + ' "' + msg + '"')


def format_timestamp(timestamp):
    l_time = time.gmtime(timestamp + 8 * 60 * 60)
    return time.strftime("%Y-%m-%d %H:%M:%S", l_time)
