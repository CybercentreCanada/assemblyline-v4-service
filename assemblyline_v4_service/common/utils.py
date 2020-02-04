import signal
import sys
import ctypes

libc = ctypes.CDLL("libc.so.6")


def set_death_signal(sig=signal.SIGTERM):
    if 'linux' not in sys.platform:
        return None

    def process_control():
        return libc.prctl(1, sig)
    return process_control


class TimeoutException(Exception):
    pass


class alarm_clock:
    """A context manager that causes an exception to be raised after a timeout."""

    def __init__(self, timeout):
        self.timeout = timeout
        self.alarm_default = signal.getsignal(signal.SIGALRM)

    def __enter__(self):
        # noinspection PyUnusedLocal
        def handler(signum, frame):
            raise TimeoutException("Timeout")

        signal.signal(signal.SIGALRM, handler)

        signal.alarm(self.timeout)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        signal.alarm(0)
        signal.signal(signal.SIGALRM, self.alarm_default)
