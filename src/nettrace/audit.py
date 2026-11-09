"""Append-only audit log of every request nettrace sends (or refuses to send).

One JSON object per line in ~/.local/state/nettrace/audit.log (override: NETTRACE_AUDIT_LOG).
Records the request only: never responses, credentials or tokens. Writing is best effort; a
logging failure must never break a trace.
"""

from __future__ import annotations

import contextlib
import contextvars
import getpass
import json
import logging
import os
import time
from collections.abc import Iterator
from logging.handlers import RotatingFileHandler
from typing import Any

DEFAULT_PATH = "~/.local/state/nettrace/audit.log"
MAX_REQUEST = 1000  # characters kept per request
_mode: contextvars.ContextVar[str] = contextvars.ContextVar("nettrace_audit_mode", default="trace")
_handlers: dict[str, RotatingFileHandler] = {}
_demo = False  # set by the demo lab: records then carry demo=true so they are not read as real device activity


def mark_demo() -> None:
    global _demo
    _demo = True


class _PrivateRotatingHandler(RotatingFileHandler):
    """Files (including ones created by rotation) are 0600; errors are swallowed."""

    def _open(self) -> Any:
        # O_NOFOLLOW: a symlinked audit.log is refused (OSError, swallowed by log()) instead of appended through.
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with contextlib.suppress(OSError):
            os.fchmod(fd, 0o600)  # an older, wider file is tightened
        return os.fdopen(fd, self.mode, encoding=self.encoding)

    def handleError(self, record: logging.LogRecord) -> None:  # noqa: N802
        pass


@contextlib.contextmanager
def mode(name: str) -> Iterator[None]:
    """Label records written inside the block (`trace` is the default, the web console uses `console`)."""
    token = _mode.set(name)
    try:
        yield
    finally:
        _mode.reset(token)


def _handler() -> RotatingFileHandler:
    path = os.path.expanduser(os.environ.get("NETTRACE_AUDIT_LOG") or DEFAULT_PATH)
    if path not in _handlers:
        folder = os.path.dirname(path) or "."
        if os.path.islink(folder):
            raise OSError(f"audit log directory {folder} is a symlink; refusing to follow it")
        existed = os.path.isdir(folder)
        os.makedirs(folder, mode=0o700, exist_ok=True)
        if not existed:
            os.chmod(folder, 0o700)  # makedirs applies the mode to parents only through the umask
        h = _PrivateRotatingHandler(path, maxBytes=5_000_000, backupCount=5, encoding="utf-8", delay=True)
        h.setFormatter(logging.Formatter("%(message)s"))
        _handlers[path] = h
    return _handlers[path]


def log(kind: str, device: str, request: str, status: str) -> None:
    """kind: ssh|panos|scm|aws (web server: trace). status: ok|refused|error (web trace cancel: cancelled)."""
    try:
        try:
            user = getpass.getuser()
        except Exception:
            user = "?"
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "pid": os.getpid(), "user": user, "mode": _mode.get(),
                  "device": device, "kind": kind, "request": str(request)[:MAX_REQUEST], "status": status}
        if _demo:
            record["demo"] = True
        _handler().handle(logging.makeLogRecord({"msg": json.dumps(record), "levelno": logging.INFO}))
    except Exception:  # noqa: S110  audit failure must never break a trace
        pass


def refused(exc: Exception, kind: str, device: str, request: str) -> None:
    """Log a ReadOnlyViolation once; callers further up the stack see `exc.audited` and skip it."""
    if not getattr(exc, "audited", False):
        exc.audited = True  # type: ignore[attr-defined]
        log(kind, device, request, "refused")
