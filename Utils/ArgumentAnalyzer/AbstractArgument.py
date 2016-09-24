import ex


class AbstractArgument(object):
    """
    Abstract Argument.
    """
    def __init__(self, arg_tag, accept_params):
        if not isinstance(arg_tag, basestring) or accept_params < 0:
            raise ex.ArgumentAnalyzerException("Bad Argument Object")

        self.acceptParam = accept_params
        self.argTag = arg_tag

    def validate(self):
        pass


class AbstractOptionArgument(AbstractArgument):
    """
    Represent an Option Argument, e.g. -h --help ...
    """
    def __init__(self, arg_tag, opt_longname, opt_shortname, accept_params):
        if (opt_shortname is None or not isinstance(opt_shortname, basestring)) \
                and (opt_longname is None or not isinstance(opt_longname, basestring)):
            raise ex.ArgumentAnalyzerException("Bad Argument Object")

        self.longName = opt_longname
        self.shortName = opt_shortname

        AbstractArgument.__init__(self, arg_tag, accept_params)


class AbstractCommandArgument(AbstractArgument):
    """
    Represent a Command Argument, e.g. merge, delete ...
    """
    def __init__(self, arg_tag, cmd_name, accept_params):
        if cmd_name is None or not isinstance(cmd_name, basestring):
            raise ex.ArgumentAnalyzerException("Bad Argument Object")

        self.cmdName = cmd_name

        AbstractArgument.__init__(self, arg_tag, accept_params)

