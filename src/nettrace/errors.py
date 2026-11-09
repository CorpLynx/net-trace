import threading
import time


class NetTraceError(Exception):
    """Base error. Messages are shown to the user without a traceback."""


class InventoryError(NetTraceError):
    pass


class CredentialError(NetTraceError):
    pass


class ReadOnlyViolation(NetTraceError):
    """Raised when code tries to send anything that is not a read-only request."""


class DeviceError(NetTraceError):
    pass


class DeadlineExceeded(NetTraceError):
    """The overall trace time budget ran out; the trace ends INCOMPLETE and keeps the hops so far."""


class Cancelled(NetTraceError):
    """The user cancelled the trace; the trace ends INCOMPLETE ("cancelled by user") and keeps the hops so far."""


class CancelToken:
    """Neutral, thread-safe cancel flag (a threading.Event wrapper). Whoever owns a trace sets it; the engine only
    looks at it through Deadline.check(), so it is honoured at exactly the points the time budget is."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


class Deadline:
    """Overall wall-clock budget for one trace, plus an optional cancel token. Every request path calls check()
    before it sends anything.
    shortcut: a request already in flight is bounded by its own timeout, not interrupted; upgrade: none needed."""

    def __init__(self, seconds: float, cancel: CancelToken | None = None):
        self.seconds = seconds
        self.cancel = cancel
        self._end = time.monotonic() + seconds

    def check(self) -> None:
        if self.cancel is not None and self.cancel.cancelled:
            raise Cancelled("cancelled by user")
        if time.monotonic() > self._end:
            raise DeadlineExceeded(f"trace deadline of {self.seconds:g}s exceeded (--timeout / trace_timeout)")
