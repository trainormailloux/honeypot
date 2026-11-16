"""Low-interaction honeypot. Emulates services, logs every attempt, and alerts you.

    python honeypot_main.py             start the honeypots + dashboard
    python honeypot_main.py --no-dash   services only (no dashboard)

Nothing here ever gives an attacker a real shell or executes anything they send.
"""
import argparse
import signal
import sys
import time

from honeypot import config
from honeypot.dashboard import serve
from honeypot.notify import Notifier
from honeypot.services.generic import GenericListener
from honeypot.services.http import HTTPListener
from honeypot.services.ssh import SSHListener
from honeypot.services.telnet import TelnetListener

SERVICES = {"ssh": SSHListener, "http": HTTPListener, "telnet": TelnetListener}


def main():
    ap = argparse.ArgumentParser(description="Low-interaction honeypot")
    ap.add_argument("--no-dash", action="store_true", help="don't start the dashboard")
    args = ap.parse_args()

    cfg = config.load()
    store_mod = __import__("honeypot.store", fromlist=["Store"])
    store = store_mod.Store()
    notifier = Notifier(cfg)
    if notifier.enabled:
        print("[*] Telegram alerts: on")
    else:
        print("[*] Telegram alerts: off (set TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID in .env to enable)")

    bind = cfg.get("bind", "0.0.0.0")
    listeners = []

    for name, ports in cfg.get("services", {}).items():
        cls = SERVICES.get(name)
        if not cls:
            continue
        for port in (ports if isinstance(ports, list) else [ports]):
            listeners.append(cls(port, store, notifier, cfg, bind=bind))

    for port in cfg.get("extra_tcp_ports", []):
        listeners.append(GenericListener(port, store, notifier, cfg, bind=bind))

    if not listeners:
        sys.exit("No services configured. Check [services] in config.toml.")

    for lst in listeners:
        lst.start()
    time.sleep(0.3)

    srv = None
    if not args.no_dash:
        d = cfg.get("dashboard", {})
        try:
            srv = serve(store, d.get("host", "127.0.0.1"), d.get("port", 8888))
        except OSError as e:
            print(f"[dashboard] could not start ({e}); honeypots keep running")

    print(f"[*] {len(listeners)} honeypot service(s) running. Ctrl+C to stop.")
    print("[*] Reminder: only expose this on a network/host you own and have isolated.")

    def shutdown(*_):
        print("\n[*] Stopping…")
        for lst in listeners:
            lst.stop()
        if srv:
            srv.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    try:
        signal.signal(signal.SIGTERM, shutdown)
    except (ValueError, AttributeError):
        pass
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
