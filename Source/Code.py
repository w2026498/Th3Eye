import sys
import subprocess
import time
import re
from collections import defaultdict
from scapy.all import *

print("=" * 80)
print("  Wireless Attack Detection - NORMAL TRAFFIC VERSION")
print("=" * 80)

# ─────────────────────────────────────────────────────────────────────────────
# 1. MONITOR MODE SETUP
# ─────────────────────────────────────────────────────────────────────────────
default_iface = "wlan0"
print("\n=== Monitor Mode Setup ===")
if input("Run 'sudo airmon-ng check kill'? (y/n): ").strip().lower() == 'y':
    subprocess.run(["sudo", "airmon-ng", "check", "kill"])

if input(f"Run 'sudo airmon-ng start {default_iface}'? (y/n): ").strip().lower() == 'y':
    result = subprocess.run(["sudo", "airmon-ng", "start", default_iface], capture_output=True, text=True)
    print(result.stdout)
    monitor_iface = None
    for line in result.stdout.splitlines():
        m = re.search(r'(wlan\d+mon|mon\d+|prism\d+)', line)
        if m:
            monitor_iface = m.group(1)
            break
    if monitor_iface:
        iface = monitor_iface
        print(f"Detected monitor interface: {default_iface}")
    else:
        iface = input("Enter the exact monitor-mode interface name: ").strip()

print(f"\nUsing monitor interface: {iface}")

# ─────────────────────────────────────────────────────────────────────────────
# 2. ATTACK TYPE SELECTION
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("=== Select Attacks to Include in Baseline Learning ===")
print("""
  [1]  Deauthentication Attack       (aireplay-ng -0)
  [2]  Beacon Flood Attack           (mdk3/mdk4 b)
  [3]  Probe Request Flood           (mass probe requests per MAC)
  [4]  Authentication/Assoc Flood    (fake auth/assoc frames)
  [5]  Evil Twin / Rogue AP          (duplicate BSSID on different channel)
  [6]  PMKID / EAPOL Handshake       (WPA handshake capture bursts)
  [7]  CTS/RTS Flood                 (control frame DoS)
  [8]  TKIP MIC Failure              (malformed TKIP injection)
  [9]  Null Function / Power-Save DoS(spoofed null frames)
  [10] ICMP/ARP Replay               (ARP replay flood per source MAC)
  [11] Fragmentation Attack          (fragmented frame flood per MAC)
  [A]  All of the above
""")

selection = input("Enter comma-separated numbers (e.g. 1,3,5) or 'A' for all: ").strip().upper()

ALL_ATTACKS = list(range(1, 12))
if selection == 'A':
    selected = ALL_ATTACKS
else:
    try:
        selected = [int(x.strip()) for x in selection.split(',') if x.strip().isdigit()]
        selected = [s for s in selected if s in ALL_ATTACKS]
    except ValueError:
        print("Invalid selection. Defaulting to all.")
        selected = ALL_ATTACKS

attack_names = {
    1:  "Deauthentication",
    2:  "Beacon Flood",
    3:  "Probe Request Flood",
    4:  "Auth/Assoc Flood",
    5:  "Evil Twin / Rogue AP",
    6:  "PMKID / EAPOL",
    7:  "CTS/RTS Flood",
    8:  "TKIP MIC Failure",
    9:  "Null Function / Power-Save DoS",
    10: "ICMP/ARP Replay",
    11: "Fragmentation Attack",
}

print(f"\nLearning baselines for: {', '.join(attack_names[s] for s in selected)}")

# ─────────────────────────────────────────────────────────────────────────────
# 3. SELECT SOURCE
# ─────────────────────────────────────────────────────────────────────────────
print("\n=== Baseline Source ===")
print("Choose how to learn NORMAL traffic:")
print("  1. Load a clean/normal pcap file (recommended)")
print("  2. Live capture on a specific channel (ensure NO attacks are running)")
choice = input("Enter 1 or 2: ").strip()

# Counters / accumulators for all attack types
counts = defaultdict(int)          # simple integer counters
probe_per_mac   = defaultdict(int) # probe requests per source MAC
arp_per_mac     = defaultdict(int) # ARP replay per source MAC
frag_per_mac    = defaultdict(int) # fragmented frames per MAC
bssid_channels  = defaultdict(set) # BSSID → set of observed channels
duration_minutes = 0

# ─── Packet analysis function ────────────────────────────────────────────────
def analyse_packet(pkt):
    if not pkt.haslayer(Dot11):
        return

    dot11 = pkt[Dot11]
    ptype   = dot11.type
    subtype = dot11.subtype
    src_mac = dot11.addr2 or ""
    bssid   = dot11.addr3 or dot11.addr1 or ""

    # 1. Deauthentication (type=0 mgmt, subtype=12)
    if 1 in selected and ptype == 0 and subtype == 12:
        counts[1] += 1

    # 2. Beacon Flood (type=0 mgmt, subtype=8)
    if 2 in selected and ptype == 0 and subtype == 8:
        counts[2] += 1

    # 3. Probe Request Flood (type=0 mgmt, subtype=4)
    if 3 in selected and ptype == 0 and subtype == 4:
        counts[3] += 1
        probe_per_mac[src_mac] += 1

    # 4. Auth / Association Flood (subtypes 0=assoc-req, 2=reassoc-req, 11=auth)
    if 4 in selected and ptype == 0 and subtype in (0, 2, 11):
        counts[4] += 1

    # 5. Evil Twin / Rogue AP – track BSSID→channel combos (needs RadioTap)
    if 5 in selected and ptype == 0 and subtype == 8 and bssid:
        ch = None
        if pkt.haslayer(RadioTap):
            ch = getattr(pkt[RadioTap], 'Channel', None)
        if ch:
            bssid_channels[bssid].add(ch)
            if len(bssid_channels[bssid]) > 1:
                counts[5] += 1   # same BSSID seen on multiple channels

    # 6. PMKID / EAPOL (EAP over LAN inside data frames)
    if 6 in selected and pkt.haslayer(EAPOL):
        counts[6] += 1

    # 7. CTS / RTS Flood (type=1 control, subtype=11=RTS, 12=CTS)
    if 7 in selected and ptype == 1 and subtype in (11, 12):
        counts[7] += 1

    # 8. TKIP MIC Failure – look for WPA TKIP data frames (type=2, protected bit set)
    if 8 in selected and ptype == 2:
        fc = dot11.FCfield if hasattr(dot11, 'FCfield') else 0
        if fc & 0x40:  # Protected bit
            counts[8] += 1

    # 9. Null Function / Power-Save (type=2 data, subtype=4 null, subtype=12 QoS-null)
    if 9 in selected and ptype == 2 and subtype in (4, 12):
        counts[9] += 1

    # 10. ARP Replay (ARP inside data frames, count per source MAC)
    if 10 in selected and pkt.haslayer(ARP):
        counts[10] += 1
        arp_per_mac[src_mac] += 1

    # 11. Fragmentation Attack (MF bit set in FC = more fragments)
    if 11 in selected and ptype == 2:
        fc = dot11.FCfield if hasattr(dot11, 'FCfield') else 0
        if fc & 0x04:  # More Fragments bit
            counts[11] += 1
            frag_per_mac[src_mac] += 1

# ─── Load pcap or live capture ───────────────────────────────────────────────
if choice == "1":
    pcap_path = input("\nEnter full path to normal/clean pcap file: ").strip()
    print(f"Reading normal traffic from: {pcap_path} ...")
    try:
        packets = rdpcap(pcap_path)
        for pkt in packets:
            analyse_packet(pkt)
        duration_minutes = 15
        print(f"Finished reading {len(packets)} packets.")
    except Exception as e:
        print(f"Error reading pcap: {e}")
        sys.exit(1)

else:
    channel = input("Enter the channel to monitor (e.g. 6): ").strip()
    subprocess.run(["sudo", "iwconfig", iface, "channel", channel])
    print(f"Set {iface} to channel {channel}")

    while True:
        try:
            duration_minutes = int(input("Enter monitoring duration in minutes (10-20): "))
            if 10 <= duration_minutes <= 20:
                break
            print("Please choose between 10 and 20.")
        except ValueError:
            print("Invalid input.")

    print(f"\nCapturing NORMAL traffic on channel {channel} for {duration_minutes} minutes...")
    print("Make sure NO attacks are running during this phase!\n")
    sniff(iface=iface, prn=analyse_packet, timeout=duration_minutes * 60, store=0)

# ─────────────────────────────────────────────────────────────────────────────
# 4. CALCULATE AVERAGES & THRESHOLDS
# ─────────────────────────────────────────────────────────────────────────────
if duration_minutes == 0:
    duration_minutes = 1  # safety guard

averages   = {}
thresholds = {}

for attack_id in selected:
    avg = counts[attack_id] / duration_minutes
    averages[attack_id]   = avg
    thresholds[attack_id] = avg * 3.0   # 3× normal = alert threshold

# Per-MAC averages (for flood attacks)
probe_avg_per_mac = (sum(probe_per_mac.values()) / len(probe_per_mac) / duration_minutes) if probe_per_mac else 0.0
arp_avg_per_mac   = (sum(arp_per_mac.values())   / len(arp_per_mac)   / duration_minutes) if arp_per_mac   else 0.0
frag_avg_per_mac  = (sum(frag_per_mac.values())  / len(frag_per_mac)  / duration_minutes) if frag_per_mac  else 0.0

print("\n" + "=" * 80)
print("BASELINE FROM NORMAL TRAFFIC ESTABLISHED")
print("=" * 80)
for attack_id in selected:
    print(f"  [{attack_id:2d}] {attack_names[attack_id]:<35s} "
          f"avg: {averages[attack_id]:8.2f}/min   threshold: {thresholds[attack_id]:8.2f}/min")
if 3 in selected:
    print(f"       Probe flood avg per MAC : {probe_avg_per_mac:.2f}/min   threshold: {probe_avg_per_mac*3:.2f}/min")
if 10 in selected:
    print(f"       ARP replay avg per MAC  : {arp_avg_per_mac:.2f}/min   threshold: {arp_avg_per_mac*3:.2f}/min")
if 11 in selected:
    print(f"       Frag attack avg per MAC : {frag_avg_per_mac:.2f}/min   threshold: {frag_avg_per_mac*3:.2f}/min")
print("=" * 80)

# ─────────────────────────────────────────────────────────────────────────────
# 5. AUTO-GENERATE DETECTOR SCRIPT
# ─────────────────────────────────────────────────────────────────────────────

# Build threshold dict string for code generation
thresh_dict_lines = []
for attack_id in selected:
    thresh_dict_lines.append(f"    {attack_id}: {thresholds[attack_id]:.4f},  # {attack_names[attack_id]}")
thresh_dict_str = "\n".join(thresh_dict_lines)

selected_str = repr(selected)

new_code = f'''#!/usr/bin/env python3
# =====================================================================
# AUTO-GENERATED Wireless Attack Real-Time Detector
# Generated : {time.strftime("%Y-%m-%d %H:%M:%S")}
# Interface : {iface}
# Monitored : {", ".join(attack_names[s] for s in selected)}
# =====================================================================

from scapy.all import *
from collections import defaultdict
import time

IFACE = "{iface}"
WINDOW = 60  # seconds per monitoring window

# Attack names
ATTACK_NAMES = {{
    1:  "Deauthentication",
    2:  "Beacon Flood",
    3:  "Probe Request Flood",
    4:  "Auth/Assoc Flood",
    5:  "Evil Twin / Rogue AP",
    6:  "PMKID / EAPOL",
    7:  "CTS/RTS Flood",
    8:  "TKIP MIC Failure",
    9:  "Null Function / Power-Save DoS",
    10: "ICMP/ARP Replay",
    11: "Fragmentation Attack",
}}

# Learned thresholds (packets/min at 3× normal baseline)
THRESHOLDS = {{
{thresh_dict_str}
}}

# Per-MAC thresholds
THRESH_PROBE_PER_MAC = {probe_avg_per_mac * 3:.4f}
THRESH_ARP_PER_MAC   = {arp_avg_per_mac   * 3:.4f}
THRESH_FRAG_PER_MAC  = {frag_avg_per_mac  * 3:.4f}

SELECTED = {selected_str}

print("=" * 70)
print("Wireless Attack Real-Time Detector  (auto-generated)")
print(f"Interface : {{IFACE}}   Window : {{WINDOW}}s")
print(f"Monitoring: {{', '.join(ATTACK_NAMES[s] for s in SELECTED)}}")
print("=" * 70)

def monitor_loop():
    while True:
        counts       = defaultdict(int)
        probe_mac    = defaultdict(int)
        arp_mac      = defaultdict(int)
        frag_mac     = defaultdict(int)
        bssid_chans  = defaultdict(set)

        def analyse(pkt):
            if not pkt.haslayer(Dot11):
                return
            dot11   = pkt[Dot11]
            ptype   = dot11.type
            subtype = dot11.subtype
            src_mac = dot11.addr2 or ""
            bssid   = dot11.addr3 or dot11.addr1 or ""

            if 1 in SELECTED and ptype == 0 and subtype == 12:
                counts[1] += 1
            if 2 in SELECTED and ptype == 0 and subtype == 8:
                counts[2] += 1
            if 3 in SELECTED and ptype == 0 and subtype == 4:
                counts[3] += 1
                probe_mac[src_mac] += 1
            if 4 in SELECTED and ptype == 0 and subtype in (0, 2, 11):
                counts[4] += 1
            if 5 in SELECTED and ptype == 0 and subtype == 8 and bssid:
                ch = None
                if pkt.haslayer(RadioTap):
                    ch = getattr(pkt[RadioTap], "Channel", None)
                if ch:
                    bssid_chans[bssid].add(ch)
                    if len(bssid_chans[bssid]) > 1:
                        counts[5] += 1
            if 6 in SELECTED and pkt.haslayer(EAPOL):
                counts[6] += 1
            if 7 in SELECTED and ptype == 1 and subtype in (11, 12):
                counts[7] += 1
            if 8 in SELECTED and ptype == 2:
                fc = dot11.FCfield if hasattr(dot11, "FCfield") else 0
                if fc & 0x40:
                    counts[8] += 1
            if 9 in SELECTED and ptype == 2 and subtype in (4, 12):
                counts[9] += 1
            if 10 in SELECTED and pkt.haslayer(ARP):
                counts[10] += 1
                arp_mac[src_mac] += 1
            if 11 in SELECTED and ptype == 2:
                fc = dot11.FCfield if hasattr(dot11, "FCfield") else 0
                if fc & 0x04:
                    counts[11] += 1
                    frag_mac[src_mac] += 1

        sniff(iface=IFACE, prn=analyse, timeout=WINDOW, store=0)

        print(f"\\n[{{time.strftime('%H:%M:%S')}}] --- Window Report ---")
        alerts = []

        for attack_id in SELECTED:
            c = counts[attack_id]
            t = THRESHOLDS.get(attack_id, 0)
            status = "*** ALERT ***" if c > t else "OK"
            print(f"  [{{attack_id:2d}}] {{ATTACK_NAMES[attack_id]:<35s}} {{c:6d}} pkts  (thresh {{t:.1f}})  {{status}}")
            if c > t:
                alerts.append(attack_id)

        # Per-MAC flood checks
        for mac, n in probe_mac.items():
            if THRESH_PROBE_PER_MAC > 0 and n > THRESH_PROBE_PER_MAC:
                print(f"       *** PROBE FLOOD from {{mac}}: {{n}} probes (thresh {{THRESH_PROBE_PER_MAC:.1f}}) ***")
                if 3 not in alerts: alerts.append(3)

        for mac, n in arp_mac.items():
            if THRESH_ARP_PER_MAC > 0 and n > THRESH_ARP_PER_MAC:
                print(f"       *** ARP REPLAY from {{mac}}: {{n}} ARP frames (thresh {{THRESH_ARP_PER_MAC:.1f}}) ***")
                if 10 not in alerts: alerts.append(10)

        for mac, n in frag_mac.items():
            if THRESH_FRAG_PER_MAC > 0 and n > THRESH_FRAG_PER_MAC:
                print(f"       *** FRAG ATTACK from {{mac}}: {{n}} frags (thresh {{THRESH_FRAG_PER_MAC:.1f}}) ***")
                if 11 not in alerts: alerts.append(11)

        if alerts:
            print(f"\\n  !!! ATTACKS DETECTED: {{[ATTACK_NAMES[a] for a in alerts]}} !!!")
            print("  Investigate nearby devices / BSSIDs immediately.")
        else:
            print("  All clear. Normal traffic levels.")

        time.sleep(1)

monitor_loop()
'''

output_file = "wireless_attack_detector.py"
with open(output_file, "w") as f:
    f.write(new_code)

print(f"\nDetector script '{output_file}' created successfully!")
print("To start real-time protection, run:")
print(f"   sudo python3 {output_file}")
print("\nRe-run this learner with a different pcap to refresh the baseline.")
print("=" * 80)
