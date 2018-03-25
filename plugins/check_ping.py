"""
Ping checker module.
"""
import os
import sys

plugindir = os.path.realpath(os.path.dirname(__file__))
sys.path.append(plugindir)

from generic import GenericJob, JobFail

class Job(GenericJob):
    def __init__(self, data):
        GenericJob.__init__(self, data)
        self.name = "ping"
        self.severity = 3
        self.ipaddr = self.config.get("ipaddr")
        if self.ipaddr is None:
            raise JobFail("no ipaddr in config: %s" % str(self.config))
        self.timeout = self.config.get("timeout", 500)

    def __call__(self):
        try:
            self.ping()
            return self.fmt_result(0)
        except JobFail as exc:
            return self.fmt_result(1, "%(ipaddr)s not alive (%(timeout)dms)",
                                   {"ipaddr": self.ipaddr, "timeout": self.timeout})

    def ping(self):
        cmd = "fping -t %d %s" % (self.timeout, self.ipaddr)
        ret = os.system(cmd + " >/dev/null 2>&1")
        self.log.debug("%s => %d", cmd, ret)
        if ret != 0:
            raise JobFail


