# WPA Handshake Capture Lab

An interactive, single-script lab for capturing **WPA1/WPA2/WPA3 handshakes** on networks **you own or are explicitly authorized to audit**.

Two strategies behind one menu:

- **Monitor flow** — classic `aircrack-ng` / `hcxdumptool` capture (WPA2 4-way handshake by deauth, WPA2 PMKID with no clients, WPA3/SAE).
- **AP-lab flow** — turns your own adapter into a WPA2 AP with `hostapd`; a client joining produces the real 4-way handshake, which is captured directly on the AP interface with `tcpdump`. **No monitor mode required** — works on cards whose monitor RX is broken (e.g. Realtek RTL8811/8821AU on modern kernels).

---

## What it does

- **Auto-installs dependencies** on first run (`aircrack-ng hcxtools hostapd dnsmasq tcpdump tshark hashcat`) via `apt`/`dnf`/`pacman`.
- **Detects your adapter's real capabilities** from the kernel (`monitor` and `AP` support) — no guesswork.
- **Proves monitor RX works** with a tcpdump frame test before claiming it does, and routes you to the AP-lab flow if it doesn't.
- Timestamps every capture so nothing overwrites.
- Restores NetworkManager cleanly on exit.

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

## Menu

```
1) Scan / select WiFi network          (monitor)
2) Capture WPA1/WPA2 handshake         (monitor)
3) Capture WPA2 PMKID                  (monitor)
4) Capture WPA3/SAE                    (monitor)
5) WPA2 lab AP (hostapd) - NO monitor  (works on any AP-capable card)
6) Diagnose capabilities/monitor RX
7) Show captured files
8) Exit
```

- **2** — scan, pick your network, then trigger a handshake (deauth a client or have one reconnect). Output: `cap-<timestamp>-01.cap`.
- **3** — `hcxdumptool` PMKID capture, needs no connected client. Output: `hash.22000`.
- **4** — `hcxdumptool` WPA3/SAE capture, needs a client connecting during the run. Output: `hash.22000`.
- **5** — the AP lab: creates an SSID on your own card. Connect a phone with the passphrase → the 4-way handshake is captured (`ap-hs-<timestamp>.pcap`), extracted to a `hashcat -m 22000` hash, and optionally demo-cracked against a generated wordlist containing your passphrase.

## Outputs

All files go to `~/lab` by default:

| File | Meaning |
|------|---------|
| `cap-*.cap` | airodump capture containing a WPA handshake |
| `hash.22000` | PMKID/WPA3 hash for `hashcat -m 22000` |
| `ap-hs-*.pcap` | EAPOL handshake captured on your own AP |
| `lab-hs-*.22000` | extracted hash from the AP lab |

## Jargon / theory

- **4-way handshake** — the WPA2 exchange between client and AP at connect time. Capturing it (plus a wordlist) is what enables offline cracking; it proves nothing about the password on its own.
- **PMKID** — a hash a WPA2/3 AP emits; lets you crack without any client being present.
- **SAE (WPA3)** — the modern replacement for the 4-way handshake; capture requires a real connection attempt.
- **Monitor mode** — the card receives every 802.11 frame on a channel, untouched by the OS. Required for passive capture.

## Legal / ethics

This tool exists for learning and security testing on **your own equipment and networks you are authorized to test**. Capturing handshakes from networks you don't own or have permission to attack is illegal in most jurisdictions. Use AGPL-grade responsibility: your lab, your gear, your consent.

## Requirements

- Linux with `sudo`
- A wireless adapter. Any adapter for the AP-lab flow; a monitor-capable card for the passive flow.
- Internet on first run (dependency install)

## Troubleshooting

- **"No networks seen" in scan** → run option 6. If the monitor RX test shows 0 frames, your card's driver can't do monitor mode on this kernel (common with in-kernel `rtw88` on Realtek 88xxAU). Use the AP-lab flow (option 5) instead.
- **Handshake doesn't appear** → reconnect a client to the target during capture; deauth only works against a client that is currently connected.
- Everything is restored on exit; if you Ctrl+C hard, run `sudo service NetworkManager restart`.