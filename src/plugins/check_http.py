"""
Ping checker module.
"""
from __future__ import print_function

import os
import sys
import requests
import hashlib

plugindir = os.path.realpath(os.path.dirname(__file__))
sys.path.append(plugindir)

from generic import GenericJob, JobFail

class Job(GenericJob):
    def __init__(self, data):
        GenericJob.__init__(self, data)
        self.name = "http"
        self.severity = 3
        self.url = self.config.get("url")
        if self.url is None:
            raise JobFail("no url in config: %s" % str(self.config))
        self.timeout = self.config.get("timeout", 1000)

    def __call__(self):
        try:
            self.request()
            return self.fmt_result(0)
        except Exception as exc:
            return self.fmt_result(1, str(exc), {})

    def request(self):
        kwargs = {
            "headers": {},
            "timeout": self.timeout,
            "verify": self.config.get("sslverify", True),
        }
        for header in self.config.get("headers", []):
            if header.get("header") in (None, ""):                               
                continue                                                         
            kwargs["headers"][header.get("header", "")] = header.get("value", "")
        if self.config.get("post_data"):
            req = requests.post
            kwargs["data"] = self.config.get("post_data")
        else:
            req = requests.get
        result = req(self.url, **kwargs)
        if result.status_code != 200:
            raise JobFail("status code %s" % result.status_code)
        op = self.config.get("op")
        if op is None:
            return
        value = self.config.get("value")
        if op is None:
            return
        content = result.content.decode()
        if op == "contains" and value not in content:
            raise JobFail("response does not contain %s" % str(value))
        elif op == "not contains" and value in content:
            raise JobFail("response contains %s" % str(value))
        elif op == "md5":
            cksum = hashlib.md5(content).hexdigest()
            if cksum != value:
                raise JobFail("md5 is not %s" % str(value))

