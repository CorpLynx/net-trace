"""Local web server for the nettrace UI (stdlib only).

Security model (it can drive read-only queries against real devices):
- binds to 127.0.0.1 only;
- every /api call needs the per-run token printed at start-up (X-Nettrace-Token header only, never the query string; the printed URL carries it in the #fragment, which browsers never send; with --open the browser gets the bare URL, never the token, and the page asks for it);
- Host header must be 127.0.0.1:<port> or localhost:<port> (blocks DNS rebinding);
- POST bodies must be JSON and at most 64 KiB; Origin, when sent, must be this server;
- POST /api/trace/cancel {id} is authenticated like every other route; it only sets a cooperative cancel flag
  on a running trace (no thread is killed), and is audit-logged (mode=trace, status=cancelled);
- device console commands still pass the same read-only guards as the CLI.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import xml.dom.minidom
import xml.etree.ElementTree as ET
from collections import OrderedDict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any

from nettrace import __version__, audit
from nettrace.errors import CancelToken, NetTraceError, ReadOnlyViolation
from nettrace.inventory import Inventory
from nettrace.models import Flow, truncate
from nettrace.netutil import PROTOCOL_NUMBERS
from nettrace.web.topology import auto_topology, overlay

MAX_BODY = 64 * 1024
CONSOLE_IDLE = 60.0  # seconds without a command before a device's console session is closed
CONSOLE_GAP = 1.0  # minimum seconds between console commands to the same device
RUN_ID_RE = re.compile(r"[A-Za-z0-9_-]{8,64}")  # client-chosen id of a running trace (for /api/trace/cancel)
CANCEL_RATE = (30, 10.0)  # at most 30 cancel calls per 10 s
TOKEN_RE = re.compile(r"[A-Za-z0-9._@\\\-]{1,64}")
ICON_KINDS = ("router", "firewall", "prisma", "tgw", "vpc-router", "eni", "host", "endpoint", "igw", "external",
              "natgw", "gwlbe", "vpce", "error", "lan", "users", "account", "peering", "vgw", "exit", "generic")

QUICK = {
    "cisco_iosxe": ["show ip interface brief", "show ip route", "show ip access-lists", "show interfaces description",
                    "show version"],
    "panos": ["show system info", "show interface all", "show routing route", "show high-availability state",
              "test security-policy-match from trust to untrust source 10.1.10.25 destination 8.8.8.8 protocol 6 "
              "destination-port 443"],
}
PANOS_CLI = {
    "show system info": ["show", "system", "info"],
    "show interface all": None,  # special-cased: <show><interface>all</interface></show>
    "show routing route": ["show", "routing", "route"],
    "show high-availability state": ["show", "high-availability", "state"],
}
# Free-form Cisco `show` stays, but never anything that reveals configuration secrets or bulk dumps.
CISCO_DENY = ("running-config", "startup-config", "tech-support", "archive", "crypto", "snmp", "aaa", "key",
              "secret", "password", "log")


class App:
    def __init__(self, inv: Inventory, *, demo: bool):
        self.inv = inv
        self.demo = demo
        if demo:
            from nettrace.demo import lab

            self.topology = lab.TOPOLOGY
            self.presets = lab.PRESETS
            self.title = "Acme Corp demo lab"
        else:
            self.topology = auto_topology(inv)
            self.presets = []
            self.title = str(inv.path)
        self.token = secrets.token_urlsafe(24)
        self.history: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.trace_slots = threading.BoundedSemaphore(2)
        self.runs_lock = threading.Lock()
        self.runs: dict[str, CancelToken] = {}  # running traces by run id
        self.cancelled_runs: OrderedDict[str, None] = OrderedDict()  # recently cancelled, so a repeat cancel is idempotent
        self._cancel_times: list[float] = []
        self.console_lock = threading.Lock()
        self._console_last: dict[str, float] = {}
        self._console_idle: dict[str, threading.Timer] = {}
        from nettrace.engine import Clients

        self.console_clients = Clients(inv)

    # ---- data ------------------------------------------------------------------------------
    def bootstrap(self) -> dict[str, Any]:
        from nettrace.viz.svg import _icon

        devices = {name: {"platform": d.platform, "site": d.site, "via": d.via, "host": d.host, "serial": d.serial,
                          "aws": bool(d.aws), "quick": QUICK.get(d.platform, [])}
                   for name, d in self.inv.devices.items()}
        return {"version": __version__, "mode": "demo" if self.demo else "live", "title": self.title,
                "topology": self.topology, "presets": self.presets, "devices": devices,
                "icons": {k: _icon(k) for k in ICON_KINDS},
                "history": self.history_list()}

    def history_list(self) -> list[dict[str, Any]]:
        return [{"id": k, "created": v["created"], "outcome": v["trace"]["Outcome"], "title": v["title"],
                 "preset": v.get("preset")} for k, v in reversed(self.history.items())]

    # ---- trace -------------------------------------------------------------------------------
    def run_trace(self, body: dict[str, Any]) -> dict[str, Any]:
        from nettrace.engine import Tracer
        from nettrace.viz import build_map, render_svg

        flow, start_at = self._flow(body)
        run_id = body.get("id")
        if run_id is None:
            run_id = secrets.token_hex(8)
        elif not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
            raise BadRequest("id: 8-64 characters from A-Z a-z 0-9 _ -")
        token = CancelToken()
        with self.runs_lock:
            if run_id in self.runs:
                raise BadRequest("id: a trace with this id is already running", HTTPStatus.CONFLICT)
            self.runs[run_id] = token
        try:
            if not self.trace_slots.acquire(timeout=1):
                raise BadRequest("another trace is running; try again in a moment", HTTPStatus.TOO_MANY_REQUESTS)
            try:
                started = time.time()
                result = Tracer(self.inv, cancel=token).trace(flow, start_at=start_at)
            finally:
                self.trace_slots.release()
        finally:
            with self.runs_lock:
                self.runs.pop(run_id, None)
        trace = result.to_dict()
        tid = secrets.token_hex(4)
        port = f":{flow.dst_port}" if flow.dst_port else ""
        entry = {
            "id": tid, "created": time.strftime("%H:%M:%S"), "elapsed_ms": int((time.time() - started) * 1000),
            "title": f"{flow.src} → {flow.dst}{port} {flow.protocol}", "preset": body.get("preset"),
            "run_id": run_id, "cancelled": result.cancelled,
            "trace": trace, "overlay": overlay(self.topology, trace),
            "map_svg": render_svg(build_map(trace), header=False),
        }
        self.history[tid] = entry
        while len(self.history) > 50:
            self.history.popitem(last=False)
        return entry

    def cancel_trace(self, body: dict[str, Any]) -> tuple[dict[str, Any], int]:
        """Ask a running trace to stop. The engine sees the flag before its next device/API request or hop, so a
        request already in flight finishes (bounded by its own timeout). Idempotent; unknown/finished id -> 404."""
        run_id = body.get("id")
        if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
            raise BadRequest("id: 8-64 characters from A-Z a-z 0-9 _ -")
        now = time.monotonic()
        with self.runs_lock:
            window = CANCEL_RATE[1]
            self._cancel_times = [t for t in self._cancel_times if now - t < window]
            if len(self._cancel_times) >= CANCEL_RATE[0]:
                raise BadRequest("too many cancel requests; wait a moment", HTTPStatus.TOO_MANY_REQUESTS)
            self._cancel_times.append(now)
            token = self.runs.get(run_id)
            if token is None:
                if run_id in self.cancelled_runs:  # repeat after the trace already stopped
                    return {"id": run_id, "status": "cancelled", "already": True}, 200
                return {"error": "no running trace with this id (unknown, or it already finished)"}, 404
            first = not token.cancelled
            token.cancel()
            if first:
                self.cancelled_runs[run_id] = None
                while len(self.cancelled_runs) > 50:
                    self.cancelled_runs.popitem(last=False)
        if first:
            audit.log("trace", "-", f"cancel run {run_id}", "cancelled")  # id only: never the access token
        return {"id": run_id, "status": "cancelling", "already": not first}, 200

    def _flow(self, b: dict[str, Any]) -> tuple[Flow, str | None]:
        def ip(key: str) -> str:
            try:
                return str(ipaddress.ip_address(str(b.get(key, "")).strip()))
            except ValueError:
                raise BadRequest(f"{key}: not an IP address") from None

        proto = str(b.get("protocol") or "tcp").lower()
        if proto not in PROTOCOL_NUMBERS and not proto.isdigit():
            raise BadRequest("protocol: unknown")
        port = b.get("port")
        port = int(port) if str(port or "").strip().isdigit() else None
        if port is not None and not 1 <= port <= 65535:
            raise BadRequest("port: must be 1-65535")
        if proto in ("tcp", "udp") and port is None:
            raise BadRequest("port: required for tcp/udp")
        opt = {}
        for key in ("application", "user"):
            v = str(b.get(key) or "").strip()
            if v:
                if not TOKEN_RE.fullmatch(v):
                    raise BadRequest(f"{key}: unsupported characters")
                opt[key] = v
        start_at = str(b.get("start_at") or "").strip() or None
        if start_at and start_at not in self.inv.devices:
            raise BadRequest("start_at: not an inventory device")
        return Flow(src=ip("src"), dst=ip("dst"), protocol=proto, dst_port=port, **opt), start_at

    # ---- console -----------------------------------------------------------------------------
    def console(self, body: dict[str, Any]) -> dict[str, Any]:
        name, command = str(body.get("device", "")), " ".join(str(body.get("command", "")).split())
        dev = self.inv.devices.get(name)
        if dev is None:
            raise BadRequest("unknown device")
        if not command or len(command) > 400:
            raise BadRequest("command: 1-400 characters")
        started = time.time()
        with self.console_lock:
            if time.monotonic() - self._console_last.get(name, -CONSOLE_GAP) < CONSOLE_GAP:
                raise BadRequest(f"wait {CONSOLE_GAP:g} s between console commands on a device",
                                 HTTPStatus.TOO_MANY_REQUESTS)
            self._console_last[name] = time.monotonic()
        kind = "ssh" if dev.platform == "cisco_iosxe" else "panos"
        with self.console_lock, audit.mode("console"):
            try:
                if dev.platform == "cisco_iosxe":
                    denied = next((t for t in CISCO_DENY if t in command.lower()), None)
                    if denied:
                        raise ReadOnlyViolation(f"console does not allow commands containing {denied!r}")
                    client = self.console_clients.device(dev)
                    client._cache.pop(command, None)  # console always re-runs
                    output = client.show(command)
                else:
                    xml_cmd = panos_cli_to_xml(command)
                    client = self.console_clients.device(dev)
                    root = client.request({"type": "op", "cmd": xml_cmd}, xml_cmd)
                    output = pretty_xml(root)
                    client.api._cache.clear()
                status = "ok"
            except ReadOnlyViolation as exc:
                audit.refused(exc, kind, name, command)
                output, status = f"refused by nettrace read-only guard: {exc}", "refused"
            except NetTraceError as exc:
                output, status = str(exc), "error"
            self._arm_idle(name)
        return {"device": name, "command": command, "status": status, "output": truncate(output),
                "elapsed_ms": int((time.time() - started) * 1000)}

    def _arm_idle(self, name: str) -> None:
        """Called with console_lock held: (re)start the idle timer for this device's console session."""
        old = self._console_idle.pop(name, None)
        if old:
            old.cancel()
        t = threading.Timer(CONSOLE_IDLE, self._idle_close, args=(name,))
        t.daemon = True
        self._console_idle[name] = t
        t.start()

    def _idle_close(self, name: str) -> None:
        with self.console_lock:
            client = self.console_clients._devices.get(name)
            if client is not None and hasattr(client, "close"):
                client.close()
            self._console_idle.pop(name, None)

    def close(self) -> None:
        for t in self._console_idle.values():
            t.cancel()
        self.console_clients.close()


def panos_cli_to_xml(command: str) -> str:
    """An exact list of PAN-OS CLI commands -> XML API op syntax. Raw XML is not accepted."""
    from nettrace.drivers.panos import build_op

    if command == "show interface all":
        return "<show><interface>all</interface></show>"
    if command in PANOS_CLI:
        return build_op(PANOS_CLI[command])
    words = command.split()
    for prefix in (["test", "security-policy-match"], ["test", "nat-policy-match"], ["test", "routing", "fib-lookup"]):
        if words[:len(prefix)] == prefix:
            rest = words[len(prefix):]
            if len(rest) % 2:
                raise BadRequest("expected key value pairs, e.g. source 10.1.1.1 destination 10.2.2.2 "
                                 "protocol 6 destination-port 443")
            return build_op(prefix, dict(zip(rest[0::2], rest[1::2], strict=True)))
    raise ReadOnlyViolation("PAN-OS console accepts only: " + ", ".join(PANOS_CLI) +
                            ", test security-policy-match|nat-policy-match|routing fib-lookup <key value ...>")


def scrubbed_env() -> dict[str, str]:
    """The environment without credentials (NETTRACE_* and AWS_*) for processes nettrace launches."""
    return {k: v for k, v in os.environ.items() if not k.startswith(("NETTRACE_", "AWS_"))}


def launch_browser(url: str) -> None:
    """Open url in the user's browser without passing it nettrace's credential variables."""
    opener = {"darwin": "open"}.get(sys.platform, "xdg-open" if sys.platform.startswith("linux") else None)
    if opener and shutil.which(opener):
        subprocess.Popen([opener, url], env=scrubbed_env(), stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        return
    # shortcut: elsewhere (Windows) the browser inherits the full environment; upgrade with os.startfile
    # from a scrubbed child process if Windows becomes a supported workstation.
    import webbrowser

    webbrowser.open(url)


def pretty_xml(root: Any) -> str:
    text = ET.tostring(root, encoding="unicode")
    pretty = xml.dom.minidom.parseString(text).toprettyxml(indent="  ")
    return "\n".join(line for line in pretty.splitlines()[1:] if line.strip())


class BadRequest(Exception):
    def __init__(self, message: str, status: HTTPStatus = HTTPStatus.BAD_REQUEST):
        super().__init__(message)
        self.status = status


# ==== HTTP =======================================================================================
PAGE_CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; "
            "img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def make_handler(app: App, port: int, verbose: bool) -> type[BaseHTTPRequestHandler]:
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    page = resources.files("nettrace.web").joinpath("static/app.html").read_text(encoding="utf-8")

    class Handler(BaseHTTPRequestHandler):
        server_version = "nettrace"
        timeout = 10  # seconds; a stalled client can't hold a thread forever
        sys_version = ""

        def log_message(self, fmt: str, *args: Any) -> None:
            if verbose:  # own line format: stdlib may re-read self.requestline; drop any query string (?token=)
                msg = re.sub(r"\?\S*|[\x00-\x1f\x7f]", "?", fmt % args)
                sys.stderr.write(f"{self.address_string()} [{self.log_date_time_string()}] {msg}\n")

        # ---- helpers -------------------------------------------------------------------------
        def _send(self, status: int, body: bytes, ctype: str, extra: dict[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, data: Any, status: int = 200) -> None:
            self._send(status, json.dumps(data, default=str).encode(), "application/json")

        def _guard(self, api: bool) -> bool:
            if self.headers.get("Host") not in allowed_hosts:
                self._send(HTTPStatus.MISDIRECTED_REQUEST, b"bad host", "text/plain")
                return False
            origin = self.headers.get("Origin")
            if origin and origin not in {f"http://{h}" for h in allowed_hosts}:
                self._send(HTTPStatus.FORBIDDEN, b"bad origin", "text/plain")
                return False
            if api and not hmac.compare_digest(self.headers.get("X-Nettrace-Token", "").encode("utf-8"), app.token.encode()):
                self._json({"error": "missing or wrong token; open the URL printed by `nettrace serve`"}, 401)
                return False
            return True

        def _body(self) -> dict[str, Any]:
            if (self.headers.get("Content-Type") or "").split(";")[0].strip() != "application/json":
                raise BadRequest("Content-Type must be application/json", HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                raise BadRequest("invalid Content-Length") from None
            if length < 0 or length > MAX_BODY:
                raise BadRequest("request too large", HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                raise BadRequest("invalid JSON") from None
            if not isinstance(data, dict):
                raise BadRequest("JSON object expected")
            return data

        # ---- routes ----------------------------------------------------------------------------
        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                if self._guard(api=False):
                    self._send(200, page.encode(), "text/html; charset=utf-8",
                               {"Content-Security-Policy": PAGE_CSP, "X-Frame-Options": "DENY"})
                return
            if not path.startswith("/api/"):
                self._send(404, b"not found", "text/plain")
                return
            if not self._guard(api=True):
                return
            if path == "/api/bootstrap":
                self._json(app.bootstrap())
            elif path == "/api/traces":
                self._json(app.history_list())
            elif path.startswith("/api/traces/"):
                entry = app.history.get(path.rsplit("/", 1)[1])
                self._json(entry if entry else {"error": "unknown trace"}, 200 if entry else 404)
            else:
                self._json({"error": "not found"}, 404)

        def do_POST(self) -> None:  # noqa: N802
            if not self._guard(api=True):
                return
            try:
                body = self._body()
                if self.path == "/api/trace":
                    self._json(app.run_trace(body))
                elif self.path == "/api/trace/cancel":
                    data, status = app.cancel_trace(body)
                    self._json(data, status)
                elif self.path == "/api/console":
                    self._json(app.console(body))
                else:
                    self._json({"error": "not found"}, 404)
            except BadRequest as exc:
                self._json({"error": str(exc)}, exc.status)
            except NetTraceError as exc:
                self._json({"error": str(exc)}, 400)
            except Exception as exc:  # never leak a traceback to the page
                self._json({"error": f"internal error: {type(exc).__name__}"}, 500)
                if verbose:
                    raise

    return Handler


def serve(inv: Inventory, *, demo: bool, port: int = 8765, open_browser: bool = False,
          verbose: bool = False, on_ready: Any = None) -> None:
    app = App(inv, demo=demo)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app, port, verbose))
    httpd.daemon_threads = True
    url = f"http://127.0.0.1:{port}/#token={app.token}"
    if on_ready:
        on_ready(url, app)
    if open_browser:
        # The tokenised URL never goes on a command line (argv is visible to `ps`); the page asks for the token.
        threading.Timer(0.4, launch_browser, args=(f"http://127.0.0.1:{port}/",)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        app.close()
