"""Catch-all TCP honeypot: logs a connection on any configured port and captures
the first bytes the client sends (useful for spotting scanners and exploit probes)."""
from honeypot.services.base import Listener


class GenericListener(Listener):
    name = "tcp"

    def handle(self, conn, ip):
        data = b""
        try:
            data = conn.recv(512)
        except OSError:
            pass
        preview = data.decode("latin-1", "replace").strip()
        preview = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in preview)[:120]
        detail = f"port {self.port}" + (f" · sent: {preview}" if preview else " · no data")
        self.log_hit(ip, detail=detail)
