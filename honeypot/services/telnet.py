"""Low-interaction Telnet honeypot: prompts for a login and logs what's entered."""
from honeypot.services.base import Listener


class TelnetListener(Listener):
    name = "telnet"

    def _readline(self, conn, limit=200):
        buf = b""
        while len(buf) < limit:
            try:
                ch = conn.recv(1)
            except OSError:
                break
            if not ch or ch in (b"\n", b"\r"):
                if buf:
                    break
                continue
            if ch[0] == 255:  # skip telnet IAC negotiation bytes
                conn.recv(2)
                continue
            buf += ch
        return buf.decode("latin-1", "replace").strip()

    def handle(self, conn, ip):
        banner = self.cfg.get("telnet", {}).get("banner", "Ubuntu 22.04 LTS")
        try:
            conn.sendall(f"\r\n{banner}\r\nlogin: ".encode())
            user = self._readline(conn)
            conn.sendall(b"Password: ")
            pw = self._readline(conn)
            conn.sendall(b"\r\nLogin incorrect\r\n")
        except OSError:
            user = pw = ""
        self.log_hit(ip, username=user or None, password=pw or None,
                     detail=None if user else "Telnet connection (no login)")
