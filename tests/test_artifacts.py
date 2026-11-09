import os
import stat

from nettrace import cli
from nettrace.demo import install
from nettrace.engine import Tracer
from nettrace.models import Flow
from nettrace.web import server


def _trace():
    return Tracer(install()).trace(Flow("10.1.10.25", "10.20.1.50", "tcp", 443)).to_dict()


def test_map_is_private_and_strips_evidence(tmp_path):
    t = _trace()
    assert any(h.get("evidence") for h in t["Hops"])
    out = tmp_path / "m.html"
    out.write_text("old")
    os.chmod(out, 0o644)
    cli.write_map([t], str(out))
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    text = out.read_text()
    assert "do not share" not in text and '"evidence"' not in text
    assert any(h.get("evidence") for h in t["Hops"])  # caller's trace is not mutated


def test_map_with_evidence_has_banner(tmp_path):
    out = tmp_path / "m.html"
    cli.write_map([_trace()], str(out), with_evidence=True)
    assert "contains device output: do not share" in out.read_text()
    svg = tmp_path / "m.svg"
    cli.write_map([_trace()], str(svg))
    assert stat.S_IMODE(svg.stat().st_mode) == 0o600


def test_temp_map_private(tmp_path, monkeypatch):
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    import tempfile
    monkeypatch.setattr(tempfile, "tempdir", None)
    path = cli.write_map([_trace()], None)
    assert path.startswith(str(tmp_path.resolve())) and stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_launch_browser_scrubs_env_and_never_gets_token(monkeypatch):
    seen = {}
    monkeypatch.setenv("NETTRACE_CISCO_PASSWORD", "x")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "y")
    monkeypatch.setattr(server.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(server.subprocess, "Popen", lambda argv, env, **kw: seen.update(argv=argv, env=env))
    monkeypatch.setattr(server.sys, "platform", "darwin")
    server.launch_browser("http://127.0.0.1:1/")
    assert seen["argv"] == ["open", "http://127.0.0.1:1/"]
    assert not any(k.startswith(("NETTRACE_", "AWS_")) for k in seen["env"]) and "PATH" in seen["env"]


def test_serve_opens_one_time_url_unless_no_open(monkeypatch):
    opened, urls = [], []

    class FakeHttpd:
        daemon_threads = False

        def __init__(self, *a):
            pass

        def serve_forever(self):
            raise KeyboardInterrupt

        def server_close(self):
            pass

    class Timer:
        def __init__(self, delay, fn, args):
            self.fn, self.args = fn, args

        def start(self):
            self.fn(*self.args)

    monkeypatch.setattr(server, "ThreadingHTTPServer", FakeHttpd)
    monkeypatch.setattr(server.threading, "Timer", Timer)
    monkeypatch.setattr(server, "launch_browser", opened.append)
    server.serve(install(), demo=True, port=1, open_browser=False, on_ready=lambda url, app: urls.append(url))
    assert opened == [] and urls[0].startswith("http://127.0.0.1:1/?c=") and "#" not in urls[0]
    server.serve(install(), demo=True, port=1, on_ready=lambda url, app: urls.append(url))  # default: open
    assert opened == [urls[1]] and urls[0] != urls[1]  # a fresh code per run; the session secret is never in the URL

