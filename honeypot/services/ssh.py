"""Low-interaction SSH honeypot: presents a real SSH handshake and logs every
login attempt, then always rejects it. No shell is ever granted."""
import socket
import threading
from pathlib import Path

import paramiko

from honeypot.services.base import Listener

ROOT = Path(__file__).resolve().parent.parent.parent
KEY_PATH = ROOT / "data" / "ssh_host_key"


def host_key():
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if KEY_PATH.exists():
        return paramiko.RSAKey(filename=str(KEY_PATH))
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(KEY_PATH))
    return key


class _Server(paramiko.ServerInterface):
    """Captures credentials; denies everything."""

    def __init__(self, on_attempt):
        self.on_attempt = on_attempt
        self.event = threading.Event()

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_password(self, username, password):
        self.on_attempt(username, password)
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.on_attempt(username, f"[publickey {key.get_name()}]")
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class SSHListener(Listener):
    name = "ssh"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.key = host_key()
        self.banner = self.cfg.get("ssh", {}).get("banner", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4")

    def handle(self, conn, ip):
        attempts = []

        def on_attempt(user, pw):
            attempts.append((user, pw))
            self.log_hit(ip, username=user, password=pw)

        t = paramiko.Transport(conn)
        t.local_version = self.banner
        t.add_server_key(self.key)
        server = _Server(on_attempt)
        try:
            t.start_server(server=server)
            # keep the transport alive briefly so the client sends its attempts
            chan = t.accept(8)
            if chan is not None:
                chan.close()
        except (paramiko.SSHException, EOFError, OSError):
            pass
        finally:
            if not attempts:
                self.log_hit(ip, detail="SSH connection (no auth attempt)")
            try:
                t.close()
            except Exception:
                pass
