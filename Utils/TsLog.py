import traceback, commands

loggerPath = "/usr/bin/logger"


def ts_log(msg, tag="TempSensServ", debug_print=True, debug_trace=True):

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
