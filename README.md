# WPA Handshake Capture Lab

An interactive lab for capturing **WPA1/WPA2/WPA3 handshakes** on networks **you own or are explicitly authorized to audit**.

Three strategies behind one menu:

- **Monitor flow** — classic `aircrack-ng` / `hcxdumptool` capture (WPA2 4-way handshake by deauth, WPA2 PMKID with no clients, WPA3/SAE).
- **AP-lab flow** — turns your own adapter into a WPA2 AP with `hostapd`; a client joining produces the real 4-way handshake, captured on the AP interface. **No monitor mode required.**
- **Virtual lab** — `mac80211_hwsim` creates software radios (AP + station + monitor) that fully emulate the flow without any real RF. Works on **any** Linux box, including cards whose monitor mode is broken.

---

## What it does

- **Auto-installs dependencies** on first run (`aircrack-ng hcxtools hostapd dnsmasq tcpdump tshark hashcat`) via `apt`/`dnf`/`pacman`.
- **Detects your adapter's real capabilities** from the kernel (`monitor` and `AP` support) — no guesswork.
- **Proves monitor RX works** with a fixed-channel airodump capture before claiming it does, and routes you to the AP-lab flow if it doesn't.
- **Separates "sees frames" from "can capture EAPOL"** — a dedicated data-frame probe distinguishes cards that pass broadcast/mgmt frames from cards that can actually capture a 4-way handshake.
- **Auto-probes on demand** — options 2/3/4 run the capability test if you skipped option 6, instead of refusing outright.
- Timestamps every capture so nothing overwrites.
- Restores NetworkManager **and reconnects WiFi** on exit (`rfkill unblock`, `nmcli device connect`).

## Monitor-mode capture method

The script does **not** use `airmon-ng start` (which creates a separate `ifacemon` vif). Some drivers — notably `mt7921e` (MediaTek MT7921/MT7922) — receive beacons on the added vif but drop data frames. The script instead sets the **main interface directly**:

```bash
sudo airmon-ng check kill
sudo ip link set wlp2s0 down
sudo iw dev wlp2s0 set type monitor
sudo ip link set wlp2s0 up
```

and captures with `airodump-ng -c <channel>` on a **fixed channel**. Avoid `iw dev ... set channel` after a scan on `mt7921e` — the card goes deaf; `airodump-ng -c` sets the channel itself.

## Known hardware limitation (mt7921e)

Even with correct monitor setup, `mt7921e` drops **all unicast frames** in monitor mode. Verified with tshark on a 4353-packet capture taken while a client reconnected: every frame's destination was `Broadcast` — zero frames addressed to the client, hence `WPA (0 handshake)` no matter how many times the phone reconnected.

EAPOL 4-way frames are unicast (AP ↔ client), so **this card can never capture a real handshake from the air**. The data-frame probe reports `DATA-RX OK` based on broadcast traffic, which is a necessary but not sufficient condition.

**Options that work on such cards:**

1. **Option 5** (AP lab) — handshake is produced by a client joining your own `hostapd` AP.
2. **Option 8** (virtual lab) — fully software-emulated, produces and cracks a real 4-way handshake offline.
3. **USB adapter** — a monitor-capable dongle that passes unicast frames (e.g. Alfa AWUS036ACH / RTL8812AU, RTL8814AU) enables the monitor flow for real-world captures.

---

## Usage

```bash
sudo ./handshake-cap.sh
```

Optional arguments:

```bash
sudo ./handshake-cap.sh <iface> [lab_dir]
```

First launch: adapters are listed, pick one by number. Missing tools are installed automatically.

### quick-capture.sh

One-shot automated capture for a single target SSID. Deletes previous `cap-*` files for that target, scans, probes DATA-RX, deauths, captures, and verifies:

```bash
sudo ./quick-capture.sh <iface> "<SSID>" [seconds]
# default: wlp2s0, "KKOCHI SAMGYUP - 2.4G", 45s
```

## Menu

```
1) Scan / select WiFi network          (monitor)
2) Capture WPA1/WPA2 handshake         (monitor)
3) Capture WPA2 PMKID                  (monitor)
4) Capture WPA3/SAE                    (monitor)
5) WPA2 lab AP (hostapd) - NO monitor  (works on this card)
6) Diagnose capabilities/monitor RX
7) Show captured files
8) Virtual WiFi lab (software, mac80211_hwsim)
9) Exit
```

- **1** — full-band scan; pick your network by number.
- **2** — capture a handshake (deauth a client or have one reconnect during the run). Output: `cap-<timestamp>-01.cap`.
- **3** — `hcxdumptool` PMKID capture, needs no connected client. Output: `hash.22000`.
- **4** — `hcxdumptool` WPA3/SAE capture, needs a client connecting during the run. Output: `hash.22000`.
- **5** — the AP lab: creates an SSID on your own card. Connect a phone with the passphrase → the 4-way handshake is captured (`ap-hs-<timestamp>.pcap`), extracted to a `hashcat -m 22000` hash, and optionally demo-cracked against a generated wordlist containing your passphrase.
- **6** — capability probe: monitor support, AP support, monitor RX (any frames), and DATA-RX (frames of type `2`, i.e. data). Menu header keeps these results.
- **8** — loads `mac80211_hwsim radios=3`, brings up AP + station + monitor interfaces, auto-connects the station to a demo SSID (`TEST-AP` / `virtpass123`), captures the handshake, extracts a `22000` hash, and runs a hashcat demo crack. Fully offline.

## Outputs

All files go to the lab dir (default `~/lab`, or the second argument):

| File | Meaning |
|------|---------|
| `cap-*.cap` | airodump capture (check with `aircrack-ng <file>`) |
| `hash.22000` | PMKID/WPA3 hash for `hashcat -m 22000` |
| `ap-hs-*.pcap` | EAPOL handshake captured on your own AP |
| `lab-hs-*.22000` | extracted hash from the AP lab |
| `hsim-hs-*.22000` | extracted hash from the virtual lab |
| `wordlist.txt` | generated demo wordlist (virtual lab) |

Verify a capture:

```bash
sudo aircrack-ng /root/lab/cap-<timestamp>-01.cap
# look for:  WPA (1 handshake)
```

Crack a `22000` hash:

```bash
hashcat -m 22000 <hash.22000> <wordlist> --force
hashcat -m 22000 <hash.22000> <wordlist> --force --show
```

## Jargon / theory

- **4-way handshake** — the WPA2 exchange between client and AP at connect time. Capturing it (plus a wordlist) is what enables offline cracking; it proves nothing about the password on its own.
- **PMKID** — a hash a WPA2/3 AP emits; lets you crack without any client being present.
- **SAE (WPA3)** — the modern replacement for the 4-way handshake; capture requires a real connection attempt.
- **Monitor mode** — the card receives every 802.11 frame on a channel, untouched by the OS. Required for passive capture.
- **Broadcast vs unicast** — broadcast/mgmt frames are delivered to any monitor; unicast frames are not, on some firmware. Handshake frames are unicast.
- **mac80211_hwsim** — in-kernel module that creates virtual WiFi radios; lets you run a full AP+client+monitor lab with zero hardware.

## Legal / ethics

This tool exists for learning and security testing on **your own equipment and networks you are authorized to test**. Capturing handshakes from networks you don't own or have permission to attack is illegal in most jurisdictions. Use AGPL-grade responsibility: your lab, your gear, your consent.

## Requirements

- Linux with `sudo`
- A wireless adapter. Any adapter for the AP-lab flow; a monitor-capable card for the passive flow (with the unicast caveat above); **no hardware needed** for the virtual lab (option 8).
- `mac80211_hwsim` kernel module for option 8 (usually built-in: `sudo modprobe mac80211_hwsim`)
- Internet on first run (dependency install)

## Troubleshooting

- **"No networks seen" in scan** → run option 6. If the monitor RX test shows 0 frames on the busiest channel, your card's driver can't do monitor mode on this kernel (common with in-kernel `rtw88` on Realtek 88xxAU). Use the AP-lab flow (option 5) or the virtual lab (option 8).
- **`DATA-RX OK` but `0 handshake`** → the card passes broadcast data but drops unicast EAPOL (typical of `mt7921e`). Confirm by checking your capture's destinations:
  ```bash
  sudo tshark -r <capture.cap> -Y 'wlan.fc.type eq 2' -T fields -e wlan.da | sort -u
  ```
  If only `Broadcast` appears, use options 5/8 or a USB adapter.
- **Handshake doesn't appear** → reconnect a client to the target during capture; deauth only works against a client that is currently connected.
- **WiFi doesn't come back after exit** → cleanup already runs `rfkill unblock`, restarts NetworkManager, and calls `nmcli device connect`. If you Ctrl+C hard:
  ```bash
  sudo systemctl restart NetworkManager wpa_supplicant
  sudo nmcli radio wifi on
  sudo nmcli device connect <iface>
  ```
- **hostapd `Could not configure driver mode`** → ensure the interface is set down → `set type ap` → up before starting hostapd (the script does this).
