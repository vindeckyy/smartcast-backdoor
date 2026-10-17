#!/usr/bin/env python3
"""
onu-tv inventory + attack surface mapper for the onn 65S4V4 (VIZIO OS).

Discovers the TV on the LAN (mDNS/SSDP like SmartCast uses), enumerates the
known SmartCast service surface, and prints the pairing-based control-API
auth token if pairing succeeds (auth is client-side; pairing is NOT a vuln,
it is the documented API flow).

Usage: python3 recon.py [TV_IP]
"""
import socket, sys, json, urllib.request, ssl, struct

KNOWN_PORTS = {
    7345:  "SCPL/lighttpd (ViziOwn /install RCE surface)",
    8000:  "SmartCast HTTP API",
    8005:  "SmartCast HTTPS API",
    9000:  "Chromecast (cast protocol)",
    9001:  "Chromecast SSL",
    10001: "SmartCast secondary",
    5555:  "ADB (if present)",
    22:    "SSH (if enabled)",
    23:    "telnet (if enabled)",
    1337:  "exploit telnetd",
    50403: "SmartCast discovery",
}

def ssdp_discover(timeout=4):
    msg = (
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n'
    ).encode()
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.settimeout(timeout)
    try:
        s.sendto(msg, ("239.255.255.250", 1900))
        while True:
            data, addr = s.recvfrom(4096)
            found.setdefault(addr[0], data.decode(errors="replace"))
    except socket.timeout:
        pass
    return found

def port_scan(ip, ports, timeout=1.5):
    open_ports = []
    for p in ports:
        s = socket.socket()
        s.settimeout(timeout)
        try:
            s.connect((ip, p))
            open_ports.append(p)
        except OSError:
            pass
        finally:
            s.close()
    return open_ports

def https_probe(ip, port, path="/"):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(
            f"https://{ip}:{port}{path}", context=ctx, timeout=6
        ) as r:
            return r.status, r.read(400).decode(errors="replace")
    except Exception as e:
        return None, str(e)

def main():
    ip = sys.argv[1] if len(sys.argv) > 1 else None
    if not ip:
        print("[*] SSDP discovery...")
        hits = ssdp_discover()
        for addr, banner in hits.items():
            if "VIZIO" in banner.upper() or "SmartCast" in banner:
                ip = addr
                print(f"[+] Candidate TV: {addr}")
                print("    " + banner.splitlines()[0] if banner else "")
        ip = ip or input("TV IP: ").strip()

    print(f"\n[*] Port scan on {ip}")
    open_ports = port_scan(ip, sorted(KNOWN_PORTS))
    for p in open_ports:
        print(f"    {p:>6} OPEN  {KNOWN_PORTS[p]}")

    if 7345 in open_ports:
        st, body = https_probe(ip, 7345, "/install")
        print(f"\n[!] Port 7345 /install -> {st}: {body[:200]}")
        print("[!] SCPL handler present => ViziOwn surface likely live.")
        print("    Next: ./viziown.sh", ip, "probe")
    if 8000 in open_ports:
        st, body = https_probe(ip, 8000, "/menu_item/dynamic?timeout=5")
        print(f"[*] Port 8000 API probe -> {st}")

if __name__ == "__main__":
    main()
