#!/bin/bash
# Control helper for the onn 65S4V4 @ 192.168.0.116 (VIZIO OS, paired)
# AUTH: pairing token from PUT /pairing/start + /pairing/pair (export AUTH=...)
TV="${TV:-192.168.0.116}"
AUTH="${AUTH:-PAIRING_TOKEN_HERE}"   # export AUTH=<token from pairing>

api() { curl -s -k --http1.1 -H "AUTH: $AUTH" --max-time 8 "https://$TV:7345$1"; }

case "${1:-info}" in
  info)      api /system/capabilities | python3 -m json.tool ;;
  location)  api /system/dynamic/iptolocation | python3 -m json.tool ;;
  pair)      TOKEN=$(curl -s -k --http1.1 -X PUT -H 'Content-Type: application/json' \
                      -d '{"DEVICE_NAME":"omp-hack","DEVICE_ID":"omp-hack-0001"}' \
                      "https://$TV:7345/pairing/start" | python3 -c 'import json,sys;print(json.load(sys.stdin)["ITEM"]["PAIRING_REQ_TOKEN"])')
             echo "token $TOKEN — enter PIN:"; read PIN
             curl -s -k --http1.1 -X PUT -H 'Content-Type: application/json' \
               -d "{\"DEVICE_NAME\":\"omp-hack\",\"DEVICE_ID\":\"omp-hack-0001\",\"CHALLENGE_TYPE\":1,\"RESPONSE_VALUE\":\"$PIN\",\"PAIRING_REQ_TOKEN\":$TOKEN}" \
               "https://$TV:7345/pairing/pair" ;;
  raw)       api "$2" ;;
  *) echo "usage: $0 [info|location|pair|raw <path>]" ;;
esac
