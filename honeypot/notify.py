"""Telegram alerts for honeypot hits, with per-IP throttling so you don't get spammed."""
import threading
import time

import requests

from honeypot.config import secret


class Notifier:
    def __init__(self, cfg, log=print):
        n = cfg.get("telegram", {})
        self.token = secret("TELEGRAM_BOT_TOKEN")
        self.chat = secret("TELEGRAM_CHAT_ID")
        self.enabled = bool(self.token and self.chat)
        self.cooldown = n.get("per_ip_cooldown_seconds", 120)
        self.log = log
        self._last = {}
        self._lock = threading.Lock()

    def _throttled(self, ip):
        now = time.time()
        with self._lock:
            if now - self._last.get(ip, 0) < self.cooldown:
                return True
            self._last[ip] = now
            return False

    def alert(self, ev):
        if not self.enabled or self._throttled(ev["ip"]):
            return
        emoji = {"ssh": "🔑", "http": "🌐", "telnet": "📟"}.get(ev["service"], "⚠")
        lines = [f"{emoji} *Honeypot hit* — {ev['service'].upper()}",
                 f"IP: `{ev['ip']}`"]
        if ev.get("port"):
            lines.append(f"Port: {ev['port']}")
        if ev.get("username") is not None:
            lines.append(f"Login: `{ev.get('username')}` / `{ev.get('password')}`")
        if ev.get("detail"):
            lines.append(ev["detail"][:200])
        lines.append(f"_{ev['ts']}_")
        self._send("\n".join(lines))

    def _send(self, text):
        try:
            requests.post(f"https://api.telegram.org/bot{self.token}/sendMessage",
                          json={"chat_id": self.chat, "text": text, "parse_mode": "Markdown"},
                          timeout=10)
        except Exception as e:  # never let a failed alert crash a listener
            self.log(f"[notify] telegram failed: {type(e).__name__}")
