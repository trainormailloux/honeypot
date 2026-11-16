"""Shared TCP listener: accepts connections and hands each to a per-service handler."""
import socket
import threading


class Listener(threading.Thread):
    name = "base"

    def __init__(self, port, store, notifier, cfg, bind="0.0.0.0", log=print):
        super().__init__(daemon=True)
        self.port, self.bind, self.store, self.notifier, self.cfg, self.log = \
            port, bind, store, notifier, cfg, log
        self._sock = None
        self._stop = threading.Event()

    def run(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.bind, self.port))
            self._sock.listen(50)
            self._sock.settimeout(1.0)
        except OSError as e:
            self.log(f"[{self.name}] cannot bind port {self.port}: {e}")
            return
        self.log(f"[{self.name}] listening on {self.bind}:{self.port}")
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._wrap, args=(conn, addr), daemon=True).start()
        self._sock.close()

    def _wrap(self, conn, addr):
        ip = addr[0]
        try:
            conn.settimeout(self.cfg.get("read_timeout_seconds", 10))
            self.handle(conn, ip)
        except Exception as e:
            self.log(f"[{self.name}] {ip} error: {type(e).__name__}")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def log_hit(self, ip, **kw):
        ev = self.store.record(self.name, ip, port=self.port, **kw)
        who = ""
        if ev.get("username") is not None:
            who = f"  {ev['username']!r}/{ev['password']!r}"
        self.log(f"[{self.name}] hit from {ip}{who}")
        self.notifier.alert(ev)
        return ev

    def handle(self, conn, ip):
        raise NotImplementedError

    def stop(self):
        self._stop.set()
