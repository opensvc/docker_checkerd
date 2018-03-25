import logging

DEFAULT_SEVERITY = 1

def lazy(fn):
    """
    A decorator for on-demand initialization of a property
    """
    attr_name = '_lazy_' + fn.__name__
    @property
    def _lazyprop(self):
        if not hasattr(self, attr_name):
            setattr(self, attr_name, fn(self))
        return getattr(self, attr_name)
    return _lazyprop

class JobFail(Exception):
    pass

class GenericJob(object):
    def __init__(self, data):
        self.name = "generic"
        self.data = data
        self.set_config()

    def set_config(self):
        """
        Use tag_data as default, tag_attach_data takes precedence.
        """
        self.config = self.data.get("tag_data")
        if self.config is None:
            self.config = {}
        self.config.update(self.data.get("tag_attach_data", {}))

    def fmt_result(self, status, fmt=None, data=None):
        if data is None:
            data = {}
        data["poller"] = self.data.get("poller")
        alert = {
            "node_id": self.data.get("node_id"),
            "svc_id": self.data.get("svc_id"),
            "dash_instance": self.data.get("tag_name"),
            "dash_type": self.name,
        }
        if status != 0:
            alert.update({
                "base_severity": self.config.get("generic", {}).get("base_severity", DEFAULT_SEVERITY),
                "dash_fmt": fmt,
                "dash_dict": data,
            })
        return {
            "status": status,
            "cid": self.data.get("cid"),
            "alert": alert,
        }

    @lazy
    def log(self):
        """
        Use a lazy property so the job can be queued.
        (loggers are not queueable)
        """
        return logging.getLogger(self.name)



