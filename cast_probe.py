#!/usr/bin/env python3
"""Probe the VIZIO OS cast receiver: try LAUNCHing candidate appIds and
listen for responses (valid/invalid) to map the receiver's app registry."""
import json, socket, ssl, struct, time, sys
sys.path.insert(0, ".")
from castv2_enum import pb_field, msg, parse_frames, parse_pb, NS_CONN, NS_HB, NS_RECV

TV = ("192.168.0.116", 8009)

CANDIDATES = [
    "E8C28D3C",                     # Backdrop (default)
    "vizio.com.vcast", "com.vizio.app",
    "YouTube", "233637DE",          # YouTube
    "NETFLIX", ".netflix",
    "amazon", "hulu",
    "app_1", "test", "dev",
]

def tx(s, src, dst, ns, payload):
    s.sendall(msg(src, dst, ns, payload))

def drain(s, secs=4):
    buf = b""; s.settimeout(secs)
    try:
        while True:
            d = s.recv(65536)
            if not d: break
            buf += d
    except (socket.timeout, ssl.SSLError, ConnectionError):
        pass
    out = []
    for f in parse_frames(buf)[0]:
        p = parse_pb(f)
        pl = p.get(6, [b""])
        pl = pl[0].decode(errors="replace") if pl and isinstance(pl[0], (bytes, bytearray)) else ""
        ns = p.get(4, [b""])[0].decode(errors="replace") if p.get(4) else ""
        if pl: out.append((ns, pl))
    return out

def main():
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(socket.create_connection(TV, timeout=8), server_hostname=TV[0])
    tx(s, "sender-0", "receiver-0", NS_CONN, json.dumps({"type": "CONNECT", "userAgent": "omp"}))
    req = 10
    for app in CANDIDATES:
        req += 1
        tx(s, "sender-0", "receiver-0", NS_RECV,
           json.dumps({"type": "LAUNCH", "appId": app, "requestId": req}))
        for ns, pl in drain(s, 3):
            try:
                j = json.loads(pl); t = j.get("type", "?")
            except Exception:
                t = "?"
            print(f"[{app:>16}] {t:<18} {pl[:220]}")
    s.close()

if __name__ == "__main__":
    main()
