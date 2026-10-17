#!/usr/bin/env python3
"""Minimal castv2 (Chromecast protocol) client — enumerates the VIZIO OS cast
receiver on 192.168.0.116:8009. Hand-rolled protobuf, no deps."""
import socket, struct, json, sys, time, ssl

TV = ("192.168.0.116", 8009)
NS_CONN = "urn:x-cast:com.google.cast.tp.connection"
NS_HB   = "urn:x-cast:com.google.cast.tp.heartbeat"
NS_RECV = "urn:x-cast:com.google.cast.receiver"

def pb_field(num, wire, data: bytes) -> bytes:
    tag = (num << 3) | wire
    out = bytes([tag]) if tag < 128 else bytes([tag & 0x7f | 0x80, tag >> 7])
    if wire == 2:
        ln = len(data)
        while True:
            b = ln & 0x7f; ln >>= 7
            out += bytes([b | (0x80 if ln else 0)])
            if not ln: break
        return out + data
    return out + data  # wire 0 handled by caller passing pre-encoded

def msg(src, dst, ns, payload: str) -> bytes:
    body = (pb_field(1, 0, b"\x00") +            # protocol_version = CASTV2_1_0
            pb_field(2, 2, src.encode()) +       # source_id
            pb_field(3, 2, dst.encode()) +       # destination_id
            pb_field(4, 2, ns.encode()) +        # namespace
            pb_field(5, 0, b"\x00") +            # payload_type = STRING
            pb_field(6, 2, payload.encode()))    # payload_utf8
    return struct.pack(">I", len(body)) + body

def parse_frames(buf: bytes):
    frames, off = [], 0
    while len(buf) - off >= 4:
        ln = struct.unpack(">I", buf[off:off+4])[0]
        if len(buf) - off - 4 < ln: break
        frames.append(buf[off+4:off+4+ln]); off += 4 + ln
    return frames, buf[off:]

def parse_pb(data: bytes):
    """Return dict of field->list of values (strings decoded)."""
    out, i = {}, 0
    while i < len(data):
        tag = 0; shift = 0
        while True:
            b = data[i]; i += 1; tag |= (b & 0x7f) << shift; shift += 7
            if not (b & 0x80): break
        num, wire = tag >> 3, tag & 7
        if wire == 2:
            ln = 0; shift = 0
            while True:
                b = data[i]; i += 1; ln |= (b & 0x7f) << shift; shift += 7
                if not (b & 0x80): break
            val = data[i:i+ln]; i += ln
            out.setdefault(num, []).append(val)
        elif wire == 0:
            v = 0; shift = 0
            while True:
                b = data[i]; i += 1; v |= (b & 0x7f) << shift; shift += 7
                if not (b & 0x80): break
            out.setdefault(num, []).append(v)
        else:
            break
    return out

def main():
    s = socket.create_connection(TV, timeout=8)
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(s, server_hostname=TV[0])
    s.sendall(msg("sender-0", "receiver-0", NS_CONN, json.dumps({"type": "CONNECT", "userAgent": "omp"})))
    s.sendall(msg("sender-0", "receiver-0", NS_RECV, json.dumps({"type": "GET_STATUS", "requestId": 1})))
    buf = b""
    s.settimeout(4)
    try:
        while True:
            data = s.recv(65536)
            if not data: break
            buf += data
    except (socket.timeout, ssl.SSLError, ConnectionError):
        pass
    frames, _ = parse_frames(buf)
    seen = 0
    for f in frames:
        d = parse_pb(f)
        payload = d.get(6, [b""])
        payload = payload[0].decode(errors="replace") if payload and isinstance(payload[0], (bytes, bytearray)) else ""
        ns = d.get(4, [b""])[0].decode(errors="replace") if d.get(4) else ""
        if not payload: continue
        seen += 1
        try:
            j = json.loads(payload)
        except Exception:
            print(f"[{ns}] {payload[:200]}"); continue
        t = j.get("type")
        if t == "RECEIVER_STATUS":
            apps = j.get("status", {}).get("applications", [])
            vol = j.get("status", {}).get("volume", {})
            print(f"receiver status: {len(apps)} running app(s), volume={vol}")
            for a in apps:
                print(json.dumps(a, indent=1))
        elif t == "PING":
            print("ping received")
        else:
            print(f"[{t}] {payload[:300]}")
    print(f"--- {seen} frames total")
    # Heartbeat check: PING to receiver
    s.sendall(msg("sender-0", "receiver-0", NS_HB, json.dumps({"type": "PING"})))
    s.settimeout(3)
    try:
        print("hb resp:", s.recv(2048)[:80])
    except socket.timeout:
        print("no hb response")

if __name__ == "__main__":
    main()
