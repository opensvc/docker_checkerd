#!/usr/bin/python

from __future__ import print_function

import os
import sys
import time
import optparse
import datetime
import json
import logging
import logging.handlers
import requests
import hashlib
import glob

from multiprocessing import Process, JoinableQueue, Queue
from subprocess import call

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
except ImportError:
    InsecureRequestWarning = None
try:
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    pass

try:
    from queue import Empty
except ImportError:
    from Queue import Empty

basedir = os.path.realpath(os.path.dirname(__file__))
sys.path.append(basedir)

import lock

DEFAULT_INTERVAL = 30
SEVERITIES = {
    "notice": 0,
    "warning": 1,
    "error": 2,
    "critical": 3,
    "alert": 4,
}
SEVERITY_NAMES = {
    0: "notice",
    1: "warning",
    2: "error",
    3: "critical",
    4: "alert",
}

def chunker(lst, length):
    i = -1
    for i in range(len(lst) // length):
        yield lst[i*length:(i+1)*length]
    yield lst[(i+1)*length:]

def config_get(param, default=None):
    if not hasattr(config, param):
        return default
    return getattr(config, param)

def fork(fn, kwargs={}):
    try:
        if os.fork() > 0:
            """ return to parent execution
            """
            return
    except:
        """ no dblogging will be done. too bad.
        """
        return

    """ separate the son from the father
    """
    os.chdir('/')
    os.setsid()
    os.umask(0)

    try:
        pid = os.fork()
        if pid > 0:
            os._exit(0)
    except:
        os._exit(1)

    fn(**kwargs)
    os._exit(0)

def dequeue_worker_int(i, q, rq):
    try:
        dequeue_worker(i, q, rq)
    except KeyboardInterrupt:
        pass

def dequeue_worker(i, q, rq):
    while True:
        job = q.get()
        if job is None:
            break
        try:
            result = job()
            rq.put(result)
        except Exception as exc:
            log = logging.getLogger("worker.%d"%i)
            log.error(exc)
        q.task_done()
    sys.exit(0)

##############################################################################
#
# Checker daemon
#
##############################################################################

class Checkerd(object):
    checkers = None
    lockfd = None
    processes = []
    last = {}
    plugins = {}

    def __init__(self, **kwargs):
        self.cf = kwargs.get("checkerd_config", "/dev/null")
        self.options = kwargs
        self.load_config()
        self.setup_log()
        self.lockfile = "/var/lock/checkerd.lock"
        self.queue = JoinableQueue()
        self.results_queue = Queue()

        for i in range(0, self.options["checkerd_workers"]):
            self.processes.append(None)

    def setup_log(self):
        self.log = logging.getLogger()
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        if self.options["checkerd_foreground"]:
            handler = logging.StreamHandler()
        else:
            logfile = os.path.join("/var/log", 'checkerd.log')
            handler = logging.handlers.RotatingFileHandler(logfile,
                                                           maxBytes=5242880,
                                                           backupCount=1)
        handler.setFormatter(formatter)
        self.log.addHandler(handler)
        self.log.setLevel(logging.INFO)

    def lock(self):
        try:
            self.lockfd = lock.lock(timeout=0, delay=0, lockfile=self.lockfile)
        except lock.lockTimeout:
            print("timed out waiting for lock")
            raise lock.lockError
        except lock.lockNoLockFile:
            print("lock_nowait: set the 'lockfile' param")
            raise lock.lockError
        except lock.lockCreateError:
            print("can not create lock file %s"%lockfile)
            raise lock.lockError
        except lock.lockAcquire as e:
            print("another daemon is currently running (pid=%s)"%e.pid)
            raise lock.lockError
        except:
            print("unexpected locking error")
            import traceback
            traceback.print_exc()
            raise lock.lockError

    def unlock(self):
        if self.lockfd is None:
            return
        lock.unlock(self.lockfd)
        self.lockfd = None

    def start_workers(self):
        for i in range(0, self.options["checkerd_workers"]):
            p = Process(target=dequeue_worker_int, args=(i, self.queue, self.results_queue), name='[worker%d]'%i)
            p.start()
            self.processes[i] = p

    def stop_workers(self):
        """ TODO: need to wait for worker idling before stop """
        for p in self.processes:
            self.queue.put(None)
        for p in self.processes:
            if p is None:
                continue
            p.join()

    @staticmethod
    def fmt_cid(data):
        tag_name = data["tag_name"]
        node_id = data.get("node_id")
        if node_id is None:
            node_id = ""
        svc_id = data.get("svc_id")
        if svc_id is None:
            svc_id = ""
        return ".".join((tag_name, node_id, svc_id))

    def enqueue_job(self, checker):
        kind = checker["tag_name"].split("::")[0]
        if kind not in self.plugins:
            return
        cid = self.fmt_cid(checker)
        last_updated = self.last.get(cid, {}).get("updated")
        now = time.time()
        if last_updated is not None and (now - last_updated) < checker.get("generic", {}).get("interval", DEFAULT_INTERVAL):
            return
        # avoid double-run at daemon startup
        if cid not in self.last:
            self.last[cid] = {
                "updated": now,
            }
        checker["poller"] = self.options["checkerd_name"]
        checker["cid"] = cid
        Job = self.plugins[kind].Job
        try:
            j = Job(checker)
        except JobFail as exc:
            self.log.error(str(exc))
            return
        self.queue.put(j, block=True)

    def get_checkers(self):
        self.checkers = self.get_node_checkers()
        self.checkers += self.get_svc_checkers()

    def get_node_checkers(self):
        params = {
            "filters": [
                "tag_name check_%::%",
                "node_tags.tag_attach_data $.generic.pollers:has:%s|$.generic.pollers[#]=0" % self.options["checkerd_name"],
            ],
            "props": ",".join([
                "tags.tag_name:tag_name",
                "tags.tag_data:tag_data",
                "node_tags.node_id:node_id",
                "node_tags.tag_attach_data:tag_attach_data",
            ]),
            "meta": False,
            "limit": 0,
        }
        return self.get("/tags/nodes", params)

    def get_svc_checkers(self):
        params = {
            "filters": [
                "tag_name check_%::%",
                "svc_tags.tag_attach_data $.generic.pollers:has:%s|$.generic.pollers[#]=0" % self.options["checkerd_name"],
            ],
            "props": ",".join([
                "tags.tag_name:tag_name",
                "tags.tag_data:tag_data",
                "svc_tags.svc_id:svc_id",
                "svc_tags.tag_attach_data:tag_attach_data",
            ]),
            "meta": False,
            "limit": 0,
        }
        return self.get("/tags/services", params)

    def get(self, path, params=None):
        path = self.options["collector_api"].rstrip("/") + path
        headers = {'content-type': 'application/json'}
        try:
            data = requests.get(path, params=params, headers=headers, auth=self.options["collector_auth"], verify=not self.options["collector_insecure"]).json()
            return data["data"]
        except Exception as exc:
            self.log.error(str(exc))
            return []

    def post(self, path, params=None, data=None):
        path = self.options["collector_api"].rstrip("/") + path
        headers = {
            'Accept' : 'application/json',
            'Content-Type' : 'application/json; charset=utf-8'
        }
        try:
            #self.log.info("POST: %s", json.dumps(data, indent=4))
            result = requests.post(path, params=params, data=json.dumps(data), headers=headers, auth=self.options["collector_auth"], verify=not self.options["collector_insecure"])
            #self.log.info(result.content)
            data = result.json()
            return data["data"]
        except Exception as exc:
            self.log.exception(exc)
            return []

    def delete(self, path, params=None, data=None):
        path = self.options["collector_api"].rstrip("/") + path
        headers = {
            'Accept' : 'application/json',
            'Content-Type' : 'application/json; charset=utf-8'
        }
        try:
            #self.log.info("DELETE: %s", json.dumps(data, indent=4))
            result = requests.delete(path, params=params, data=json.dumps(data), headers=headers, auth=self.options["collector_auth"], verify=not self.options["collector_insecure"])
            #self.log.info(result.content)
            data = result.json()
            return data["data"]
        except Exception as exc:
            self.log.exception(exc)
            return []

    def run_forever(self):
        iterations = 0
        while True:
            iterations += 1
            if iterations > self.options["checkerd_janitor_loops"] or self.checkers is None:
                # reset every <checkerd_janitor_loops> secs
                self.get_checkers()
                iterations = 0
            for checker in self.checkers:
                self.enqueue_job(checker)
            self.dequeue_results()
            time.sleep(self.options["checkerd_loop_interval"])

    def dispatch_results(self):
        to_create = []
        to_delete = []
        now = time.time()
        while True:
            try:
                result = self.results_queue.get(False)
            except Empty:
                break
            if result is None:
                continue
            status = result.get("status")
            cid = result.get("cid")
            if status == self.last.get(cid, {}).get("status") and \
               now - self.last.get(cid, {}).get("changed") < self.options["checkerd_update_unchanged_interval"]:
                # don't update the collector too often if not changed
                #self.log.info("skip %s update: unchanged", cid)
                self.last[cid]["updated"] = now
                continue
            self.log.info("send %s result", result["cid"])
            self.last[cid] = {
                "status": status,
                "changed": now,
                "updated": now,
            }
            alert = result.get("alert")
            if status == 0:
                self.log.info("%s delete: %s", cid, alert)
                to_delete.append(alert)
            else:
                self.log.info("%s create: %s", cid, alert)
                to_create.append(alert)
        return {
            "create": to_create,
            "delete": to_delete,
        }

    def delete_alerts(self, data):
        for chunk in chunker(data, 50):
            if len(chunk) == 0:
                break
            self.delete("/alerts", data=chunk)

    def create_alerts(self, data):
        for chunk in chunker(data, 50):
            if len(chunk) == 0:
                break
            self.post("/alerts", data=chunk)

    def dequeue_results(self):
        data = self.dispatch_results()
        self.delete_alerts(data["delete"])
        self.create_alerts(data["create"])

    def load_config(self):
        conf = ConfigParser.RawConfigParser()
        conf.read(self.cf)
        keywords = {
            ("collector", "api"): None,
            ("collector", "user"): None,
            ("collector", "password"): None,
            ("collector", "insecure"): False,
            ("checkerd", "foreground"): False,
            ("checkerd", "name"): "default",
            ("checkerd", "loop_interval"): 1,
            ("checkerd", "janitor_interval"): 30,
            ("checkerd", "update_unchanged_interval"): 60,
            ("checkerd", "workers"): 10,
        }
        for (section, option), default in keywords.items():
            key = section + "_" + option
            if self.options.get(key) is None:
                try:
                    self.options[key] = conf.get(section, option)
                except:
                    if default is None:
                        raise Exception("%s is mandatory" % key)
                    else:
                        self.options[key] = default
        self.options["collector_auth"] = (
            self.options["collector_user"],
            self.options["collector_password"],
        )
        self.options["collector_api"] = self.options["collector_api"].rstrip("/")
        self.options["checkerd_janitor_loops"] = self.options["checkerd_janitor_interval"] // self.options["checkerd_loop_interval"] + 1

    def load_plugins(self):
        plugindir = os.path.join(basedir, "plugins")
        sys.path.append(plugindir)
        for fpath in glob.glob(plugindir+"/*.py"):
            modname = os.path.basename(fpath[:-3])
            try:
                mod = __import__(modname)
            except ImportError as exc:
                self.log.error("plugin load failed: %s (%s)", modname, exc)
            self.log.info("plugin loaded: %s", modname)
            self.plugins[modname] = mod

    def main(self):
        self.load_plugins()
        try:
            self.start_workers()
            self.run_forever()
        except KeyboardInterrupt:
            self.log.info("keyboard interrupt")
            pass
        finally:
            self.stop_workers()
            self.unlock()

def main(**kwargs):
    daemon = Checkerd(**kwargs)
    try:
        daemon.lock()
        if daemon.options["checkerd_foreground"]:
            daemon.main()
        else:
            fork(daemon.main)
    except lock.lockError:
        return 0
    except Exception:
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-f", "--foreground", action="store_true",
                      dest="checkerd_foreground", help="Run in foreground")
    parser.add_option("-c", "--config", action="store",
                      dest="checkerd_config", help="path to config file")
    parser.add_option("-n", "--name", action="store",
                      dest="checkerd_name", help="poller name. a poller won't run checks assigned to another poller.")
    parser.add_option("--update-unchanged-interval", action="store", type="int",
                      dest="checkerd_update_unchanged_interval", help="if a check does not change status, don't push the change to the collector until.")
    parser.add_option("--loop-interval", action="store", type="int",
                      dest="checkerd_loop_interval", help="the checking loop interval.")
    parser.add_option("--janitor-interval", action="store", type="int",
                      dest="checkerd_janitor_interval", help="the interval between checkers config refresh. Don't push to low on loaded collectors.")
    parser.add_option("-u", "--user", action="store",
                      dest="collector_user", help="the collector user name to connect the collector.")
    parser.add_option("-p", "--password", action="store",
                      dest="collector_password", help="the collector user password to connect the collector.")
    parser.add_option("--api", action="store",
                      dest="collector_api", help="the collector url to connect.")
    parser.add_option("--insecure", action="store_true",
                      dest="collector_insecure", help="disable ssl validations.")
    parser.add_option("--workers", action="store", type="int",
                      dest="checkerd_workers", help="the number of workers to start.")
    options, _ = parser.parse_args()
    options = vars(options)
    sys.exit(main(**options))
