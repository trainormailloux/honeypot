"""Low-interaction HTTP honeypot: serves a fake admin login page and logs every
request and every set of credentials submitted. Always returns 'invalid login'."""
from honeypot.services.base import Listener
from urllib.parse import parse_qs, unquote_plus

LOGIN_PAGE = """<!DOCTYPE html><html><head><title>Admin Login</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{{font-family:Arial,sans-serif;background:#1b1b1b;color:#ddd;display:flex;
height:100vh;align-items:center;justify-content:center;margin:0}}
.box{{background:#262626;padding:34px;border-radius:8px;width:300px;box-shadow:0 2px 20px #0008}}
h2{{margin:0 0 18px}}input{{width:100%;padding:9px;margin:6px 0;box-sizing:border-box;
border:1px solid #444;background:#1b1b1b;color:#eee;border-radius:4px}}
button{{width:100%;padding:10px;margin-top:10px;background:#2563eb;color:#fff;border:0;border-radius:4px;cursor:pointer}}
.err{{color:#f87171;font-size:13px;height:16px}}</style></head>
<body><div class="box"><h2>Router Admin</h2><div class="err">{err}</div>
<form method="post" action="/login">
<input name="username" placeholder="Username" autocomplete="off">
<input name="password" type="password" placeholder="Password">
<button type="submit">Sign in</button></form></div></body></html>"""


class HTTPListener(Listener):
    name = "http"

    def handle(self, conn, ip):
        data = conn.recv(8192).decode("latin-1", "replace")
        if not data:
            return
        line = data.split("\r\n", 1)[0]
        parts = line.split(" ")
        method = parts[0] if parts else ""
        path = parts[1] if len(parts) > 1 else "/"
        ua = ""
        for h in data.split("\r\n"):
            if h.lower().startswith("user-agent:"):
                ua = h.split(":", 1)[1].strip()

        username = password = None
        err = ""
        if method == "POST":
            body = data.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in data else ""
            form = parse_qs(body)
            username = unquote_plus(form.get("username", [""])[0])
            password = unquote_plus(form.get("password", [""])[0])
            err = "Invalid username or password"

        detail = f"{method} {path}" + (f" · UA: {ua}" if ua else "")
        self.log_hit(ip, username=username, password=password, detail=detail)

        page = LOGIN_PAGE.format(err=err).encode()
        resp = (b"HTTP/1.1 200 OK\r\nServer: nginx\r\n"
                b"Content-Type: text/html\r\nConnection: close\r\n"
                b"Content-Length: " + str(len(page)).encode() + b"\r\n\r\n" + page)
        try:
            conn.sendall(resp)
        except OSError:
            pass
