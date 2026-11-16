"""Offline tests — no real network listeners, just the logging/parsing/render logic.

    python -m unittest discover tests
"""
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from honeypot.dashboard import render
from honeypot.store import Store


class FakeConn:
    """A stand-in socket: feeds canned bytes to a handler and captures the reply."""
    def __init__(self, data=b""):
        self._in = data
        self.sent = b""
    def recv(self, n):
        chunk, self._in = self._in[:n], self._in[n:]
        return chunk
    def sendall(self, b):
        self.sent += b
    def settimeout(self, *_):
        pass
    def close(self):
        pass


def make_listener(cls, store):
    class _N:
        def alert(self, ev):
            pass
    return cls(0, store, _N(), {}, log=lambda *a: None)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.s = Store(self.d.name)

    def tearDown(self):
        self.d.cleanup()

    def test_record_and_summary(self):
        self.s.record("ssh", "1.1.1.1", 2222, username="root", password="toor")
        self.s.record("ssh", "1.1.1.1", 2222, username="admin", password="admin")
        self.s.record("http", "2.2.2.2", 8080, username="root", password="x", detail="POST /login")
        s = self.s.summary()
        self.assertEqual(s["total"], 3)
        self.assertEqual(s["unique_ips"], 2)
        self.assertEqual(s["cred_attempts"], 3)
        self.assertEqual(self.s.top("ip")[0], ("1.1.1.1", 2))
        self.assertEqual(self.s.top("username")[0], ("root", 2))
        self.assertEqual(dict(self.s.by_service())["ssh"], 2)
        self.assertEqual(len(Path(self.d.name, "events.jsonl").read_text().splitlines()), 3)

    def test_render_no_crash(self):
        html = render(self.s)                      # empty store
        self.assertIn("Honeypot", html)
        self.s.record("ssh", "9.9.9.9", 2222, username="pi", password="raspberry")
        html = render(self.s)
        self.assertIn("9.9.9.9", html)
        self.assertIn("raspberry", html)


class HTTPTests(unittest.TestCase):
    def test_captures_post_credentials(self):
        from honeypot.services.http import HTTPListener
        d = tempfile.TemporaryDirectory()
        store = Store(d.name)
        lst = make_listener(HTTPListener, store)
        req = ("POST /login HTTP/1.1\r\nHost: x\r\nUser-Agent: evilbot\r\n"
               "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
               "username=admin&password=hunter2").encode()
        conn = FakeConn(req)
        lst.handle(conn, "3.3.3.3")
        ev = store.recent(1)[0]
        self.assertEqual((ev["username"], ev["password"]), ("admin", "hunter2"))
        self.assertIn("evilbot", ev["detail"])
        self.assertIn(b"Router Admin", conn.sent)   # served the fake login page
        d.cleanup()

    def test_get_logs_request_without_creds(self):
        from honeypot.services.http import HTTPListener
        d = tempfile.TemporaryDirectory()
        store = Store(d.name)
        lst = make_listener(HTTPListener, store)
        lst.handle(FakeConn(b"GET /admin HTTP/1.1\r\nHost: x\r\n\r\n"), "4.4.4.4")
        ev = store.recent(1)[0]
        self.assertIsNone(ev["username"])
        self.assertIn("GET /admin", ev["detail"])
        d.cleanup()


class TelnetTests(unittest.TestCase):
    def test_captures_login(self):
        from honeypot.services.telnet import TelnetListener
        d = tempfile.TemporaryDirectory()
        store = Store(d.name)
        lst = make_listener(TelnetListener, store)
        lst.handle(FakeConn(b"root\r\npassword1\r\n"), "5.5.5.5")
        ev = store.recent(1)[0]
        self.assertEqual((ev["username"], ev["password"]), ("root", "password1"))
        d.cleanup()


class GenericTests(unittest.TestCase):
    def test_logs_bytes(self):
        from honeypot.services.generic import GenericListener
        d = tempfile.TemporaryDirectory()
        store = Store(d.name)
        lst = GenericListener(3389, store, _N(), {}, log=lambda *a: None)
        lst.handle(FakeConn(b"\x03\x00\x00\x13rdp-probe"), "6.6.6.6")
        ev = store.recent(1)[0]
        self.assertEqual(ev["service"], "tcp")
        self.assertIn("rdp-probe", ev["detail"])
        d.cleanup()


class _N:
    def alert(self, ev):
        pass


class NotifierTests(unittest.TestCase):
    def test_throttle(self):
        from honeypot.notify import Notifier
        n = Notifier({"telegram": {"per_ip_cooldown_seconds": 60}})
        self.assertFalse(n._throttled("1.2.3.4"))   # first time: allowed
        self.assertTrue(n._throttled("1.2.3.4"))     # immediate repeat: blocked
        self.assertFalse(n._throttled("5.6.7.8"))    # different IP: allowed


class IntegrationTests(unittest.TestCase):
    def test_http_listener_over_a_real_socket(self):
        from honeypot.services.http import HTTPListener
        d = tempfile.TemporaryDirectory()
        store = Store(d.name)
        lst = HTTPListener(0, store, _N(), {}, bind="127.0.0.1", log=lambda *a: None)
        # bind to an ephemeral port manually and run one accept
        import socket as sk
        srv = sk.socket(); srv.setsockopt(sk.SOL_SOCKET, sk.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0)); srv.listen(1)
        port = srv.getsockname()[1]
        lst.port = port

        def one():
            c, a = srv.accept()
            lst._wrap(c, a)
        th = threading.Thread(target=one); th.start()
        time.sleep(0.1)
        c = sk.create_connection(("127.0.0.1", port), timeout=3)
        c.sendall(b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=u&password=p")
        resp = c.recv(2048); c.close(); th.join(2); srv.close()
        self.assertIn(b"200 OK", resp)
        self.assertEqual(store.recent(1)[0]["username"], "u")
        d.cleanup()


if __name__ == "__main__":
    unittest.main()
