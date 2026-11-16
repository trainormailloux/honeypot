"""A small local web dashboard showing honeypot activity. Read-only, binds to
localhost by default. No external assets."""
import html
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="20"><title>Honeypot</title>
<style>
:root{{--bg:#07040f;--card:#0e0a18;--line:#231a3a;--fg:#f3eeff;--muted:#8d84aa;
--soft:#c4b5fd;--accent:#8b5cf6;--red:#f87171;--amber:#fbbf24;--green:#34d399}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 "Segoe UI",system-ui,sans-serif}}
.wrap{{max-width:1100px;margin:0 auto;padding:28px 20px 60px}}
h1{{font-size:26px;margin:0}}h1 .s{{color:var(--accent)}}
.sub{{color:var(--muted);margin-top:4px}}
.stats{{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}}
.stat{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 20px;min-width:140px}}
.stat b{{display:block;font-size:26px}}.stat span{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:1px}}
h2{{font-size:12px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);margin:34px 0 12px}}
.cols{{display:grid;grid-template-columns:1fr 1fr;gap:16px}}
@media(max-width:800px){{.cols{{grid-template-columns:1fr}}}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:16px 18px}}
table{{width:100%;border-collapse:collapse}}
th{{text-align:left;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px;
padding:6px 8px;border-bottom:1px solid var(--line)}}
td{{padding:6px 8px;border-bottom:1px solid #14102400;font-variant-numeric:tabular-nums}}
tr:hover td{{background:#120c22}}
.bar{{display:flex;align-items:center;gap:8px;padding:5px 8px}}
.bar .lab{{width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.bar .track{{flex:1;height:8px;background:#1b1430;border-radius:4px;overflow:hidden}}
.bar .fill{{height:8px;background:var(--accent)}}.bar .n{{width:40px;text-align:right;color:var(--muted)}}
.svc{{display:inline-block;font-size:11px;font-weight:700;padding:1px 7px;border-radius:99px;color:#0b0614}}
.mono{{font-family:Consolas,monospace}}.muted{{color:var(--muted)}}
.empty{{color:var(--muted);text-align:center;padding:30px}}
.foot{{color:var(--muted);font-size:12px;margin-top:40px}}
</style></head><body><div class="wrap">
<h1>🛡 Honeypot <span class="s">dashboard</span></h1>
<div class="sub">{sub}</div>
<div class="stats">{stats}</div>
<div class="cols">
<div><h2>Top attacker IPs</h2><div class="card">{ips}</div>
<h2>By service</h2><div class="card">{services}</div></div>
<div><h2>Top usernames</h2><div class="card">{users}</div>
<h2>Top passwords</h2><div class="card">{passwords}</div></div>
</div>
<h2>Recent activity</h2><div class="card">{recent}</div>
<div class="foot">Read-only · auto-refreshes every 20s · all logging, no shell access</div>
</div></body></html>"""

SVC_COLOR = {"ssh": "#8b5cf6", "http": "#34d399", "telnet": "#fbbf24", "tcp": "#60a5fa"}


def _e(x):
    return html.escape(str(x)) if x is not None else ""


def _bars(rows):
    if not rows:
        return '<div class="empty">Nothing yet.</div>'
    mx = max(n for _, n in rows) or 1
    out = []
    for v, n in rows:
        out.append(f'<div class="bar"><span class="lab mono">{_e(v)}</span>'
                   f'<span class="track"><span class="fill" style="width:{n/mx*100:.0f}%"></span></span>'
                   f'<span class="n">{n}</span></div>')
    return "".join(out)


def render(store):
    s = store.summary()
    stats = "".join(f'<div class="stat"><b>{v}</b><span>{k}</span></div>' for k, v in [
        ("total hits", s["total"]), ("unique IPs", s["unique_ips"]), ("login attempts", s["cred_attempts"])])
    svc_rows = store.by_service()
    services = "".join(
        f'<div class="bar"><span class="lab"><span class="svc" style="background:{SVC_COLOR.get(n,"#888")}">'
        f'{_e(n).upper()}</span></span><span class="track"><span class="fill" '
        f'style="width:{c/max((x[1] for x in svc_rows),default=1)*100:.0f}%;background:{SVC_COLOR.get(n,"#888")}">'
        f'</span></span><span class="n">{c}</span></div>' for n, c in svc_rows) or '<div class="empty">Nothing yet.</div>'

    rec = store.recent(60)
    if rec:
        rows = ["<table><tr><th>Time (UTC)</th><th>Service</th><th>IP</th><th>Login</th><th>Detail</th></tr>"]
        for e in rec:
            login = f'{_e(e["username"])} / {_e(e["password"])}' if e["username"] is not None else '<span class="muted">—</span>'
            rows.append(f'<tr><td class="mono">{_e(e["ts"][11:19])}</td>'
                        f'<td><span class="svc" style="background:{SVC_COLOR.get(e["service"],"#888")}">{_e(e["service"]).upper()}</span></td>'
                        f'<td class="mono">{_e(e["ip"])}</td><td class="mono">{login}</td>'
                        f'<td class="muted">{_e(e["detail"])}</td></tr>')
        rows.append("</table>")
        recent = "".join(rows)
    else:
        recent = '<div class="empty">No activity yet. Point a test connection at a honeypot port to see it here.</div>'

    sub = (f'Watching since {s["since"][:16].replace("T"," ")} UTC' if s["since"]
           else "Waiting for the first connection…")
    return PAGE.format(sub=sub, stats=stats, ips=_bars(store.top("ip")),
                       services=services, users=_bars(store.top("username")),
                       passwords=_bars(store.top("password")), recent=recent)


def serve(store, host="127.0.0.1", port=8888, log=print):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = render(store).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer((host, port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log(f"[dashboard] http://{host}:{port}")
    return srv
