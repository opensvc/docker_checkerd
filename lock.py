import fcntl
import os
import time

class lockError(Exception):
    """ generic lock error
    """

class lockTimeout(Exception):
    """ acquire lock timed out
    """

class lockNoLockFile(Exception):
    """ no lockfile specified
    """

class lockCreateError(Exception):
    """ could not create lockfile
    """

class lockAcquire(Exception):
    """ could not acquire lock on lockfile
    """
    def __init__(self, pid):
        self.pid = pid

def lock(timeout=30, delay=5, lockfile=None):
    if timeout == 0:
        return lock_nowait(lockfile)
    for i in range(timeout//delay):
        try:
            return lock_nowait(lockfile)
        except lockAcquire:
            time.sleep(delay)
    raise lockTimeout

def lock_nowait(lockfile=None):
    if lockfile is None:
        raise lockNoLockFile

    pid = 0
    dir = os.path.dirname(lockfile)

    if not os.path.exists(dir):
        os.makedirs(dir)

    try:
        with open(lockfile, 'r') as fd:
            pid = int(fd.read())
            fd.close()
    except:
        pass

    try:
        lockfd = os.open(lockfile, os.O_RDWR|os.O_SYNC|os.O_CREAT|os.O_TRUNC, 0o0644)
    except:
        raise lockCreateError

    try:
        """ test if we already own the lock
        """
        if pid == os.getpid():
            os.close(lockfd)
            return

        """ FD_CLOEXEC makes sure the lock is the held by processes
            we fork from this process
        """
        fcntl.flock(lockfd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        flags = fcntl.fcntl(lockfd, fcntl.F_GETFD)
        flags |= fcntl.FD_CLOEXEC

        """ acquire lock
        """
        fcntl.fcntl(lockfd, fcntl.F_SETFD, flags)

        """ drop our pid in the lockfile
        """
        os.write(lockfd, str(os.getpid()).encode())
        os.fsync(lockfd)
        return lockfd
    except IOError:
        raise lockAcquire(pid)
    except:
        raise

def unlock(lockfd):
    if lockfd is None:
        return
    try:
        os.close(lockfd)
    except:
        """ already released by a parent process ?
        """
        pass

