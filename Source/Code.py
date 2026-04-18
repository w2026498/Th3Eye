#!/usr/bin/env python3
# =============================================================================
#   Wireless Attack Detection — Baseline Learner
#   What this does:
#     1. Sets your wireless card to monitor mode
#     2. Asks which attack types you want to watch for
#     3. Learns what "normal" traffic looks like (from a file or live)
#     4. Saves a ready-to-run detector script based on what it learned
#
#   NEW — RSSI Location Tracking:
#     When an attack is detected, the detector reads the signal strength
#     (RSSI) of the attacking device's packets and uses it to estimate:
#       • How far away the attacker is (e.g. "Very close — under 5 metres")
#       • How strong their signal is (e.g. -45 dBm)
#       • Whether the signal is getting stronger (attacker moving closer)
#     This helps you physically locate the device causing the attack.
# =============================================================================

import sys
import os
import re
import time
import subprocess
from collections import defaultdict

# ── Check that Scapy is installed before doing anything else ─────────────────
try:
    from scapy.all import rdpcap, sniff, Dot11, RadioTap, EAPOL, ARP
except ImportError:
    print("\n[ERROR] The 'scapy' library is not installed.")
    print("        Fix it by running:  sudo pip3 install scapy --break-system-packages")
    sys.exit(1)


# =============================================================================
#   ATTACK LIST
#   These are the wireless attacks this tool can detect.
#   "Tested" = reliable results.   "Beta" = still being refined.
# =============================================================================

TESTED_ATTACKS = {
    1: "Deauthentication Attack",
    4: "Authentication / Association Flood",
}

BETA_ATTACKS = {
    2:  "Beacon Flood Attack                [BETA]",
    3:  "Probe Request Flood                [BETA]",
    5:  "Evil Twin / Rogue Access Point     [BETA]",
    6:  "PMKID / EAPOL Handshake Capture    [BETA]",
    7:  "CTS / RTS Flood                    [BETA]",
    8:  "TKIP MIC Failure                   [BETA]",
    9:  "Null Function / Power-Save DoS     [BETA]",
    10: "ICMP / ARP Replay Attack           [BETA]",
    11: "Fragmentation Attack               [BETA]",
}

# Short names used inside the generated detector script
ATTACK_SHORT_NAMES = {
    1:  "Deauthentication",
    2:  "Beacon Flood",
    3:  "Probe Request Flood",
    4:  "Auth / Assoc Flood",
    5:  "Evil Twin / Rogue AP",
    6:  "PMKID / EAPOL",
    7:  "CTS / RTS Flood",
    8:  "TKIP MIC Failure",
    9:  "Null Function / Power-Save DoS",
    10: "ICMP / ARP Replay",
    11: "Fragmentation Attack",
}


# =============================================================================
#   RSSI HELPER FUNCTIONS
#   RSSI (Received Signal Strength Indicator) is a negative number in dBm.
#   The closer to zero, the stronger the signal, meaning the device is nearby.
#
#   Examples:
#     -30 dBm = Very strong  → device is probably in the same room
#     -60 dBm = Good signal  → device is nearby, maybe next room
#     -80 dBm = Weak signal  → device is far away or through walls
#    -100 dBm = Very weak    → device is at the edge of range
# =============================================================================

def rssi_to_distance_label(rssi: int) -> str:
    """
    Turn an RSSI value (dBm) into a plain-English distance estimate.
    These ranges are approximate — walls, interference, and antenna
    type all affect real-world accuracy.
    """
    if rssi >= -50:
        return "Very close  (likely under 5 metres — same room as you)"
    elif rssi >= -60:
        return "Close       (roughly 5–15 metres — probably the next room)"
    elif rssi >= -70:
        return "Medium      (roughly 15–30 metres — same building)"
    elif rssi >= -80:
        return "Far         (roughly 30–60 metres — different floor or just outside)"
    else:
        return "Very far    (60+ metres — at the edge of Wi-Fi range)"


def rssi_to_signal_bar(rssi: int) -> str:
    """
    Turn an RSSI value into a simple visual bar so you can
    see signal strength at a glance in the terminal.
    """
    if rssi >= -50:
        return "[████████] Excellent"
    elif rssi >= -60:
        return "[██████░░] Good"
    elif rssi >= -70:
        return "[████░░░░] Fair"
    elif rssi >= -80:
        return "[██░░░░░░] Weak"
    else:
        return "[░░░░░░░░] Very Weak"


def extract_rssi(packet) -> int | None:
    """
    Pull the RSSI value out of a packet's RadioTap header.
    RadioTap is the wrapper that Wi-Fi cards put around raw 802.11 frames —
    it contains signal strength, channel, and other radio-level info.
    Returns the RSSI as an integer (e.g. -65), or None if not available.
    """
    try:
        if packet.haslayer(RadioTap):
            rt = packet[RadioTap]
            # Try the standard dBm_AntSignal field first
            if hasattr(rt, "dBm_AntSignal") and rt.dBm_AntSignal is not None:
                return int(rt.dBm_AntSignal)
    except Exception:
        pass
    return None


# =============================================================================
#   SMALL HELPER FUNCTIONS
# =============================================================================

def print_banner(title: str) -> None:
    """Print a clearly visible section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def print_section(title: str) -> None:
    """Print a smaller sub-section label."""
    print(f"\n  ── {title} ──\n")


def run_command(command: list):
    """
    Run a shell command and return the result.
    Returns None if the command fails or times out.
    """
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=30)
    except Exception:
        return None


def interface_exists(name: str) -> bool:
    """Check whether a network interface with this name actually exists."""
    return os.path.exists(f"/sys/class/net/{name}")


def interface_is_in_monitor_mode(name: str) -> bool:
    """Return True if the given interface is currently in monitor mode."""
    result = run_command(["iwconfig", name])
    return bool(result and "Monitor" in result.stdout)


def get_wireless_interfaces() -> list:
    """
    Look through the system's network interfaces and return
    any that are wireless (have a 'wireless' or 'phy80211' folder).
    """
    found = []
    try:
        for entry in os.listdir("/sys/class/net"):
            wireless_path = f"/sys/class/net/{entry}/wireless"
            phy_path      = f"/sys/class/net/{entry}/phy80211"
            if os.path.exists(wireless_path) or os.path.exists(phy_path):
                found.append(entry)
    except Exception:
        pass
    return found


def ask_yes_no(prompt: str) -> bool:
    """Ask the user a yes/no question. Keep asking until they answer properly."""
    while True:
        answer = input(f"  {prompt} (y/n): ").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("  [!] Please type 'y' or 'n'.")


def make_safe_filename(name: str) -> str:
    """
    Turn any string into a safe Python filename.
    Replaces spaces and special characters with underscores,
    and adds '.py' at the end if it's missing.
    """
    safe = re.sub(r"[^\w\-]", "_", name.strip())
    return safe if safe.endswith(".py") else safe + ".py"


# =============================================================================
#   STEP 1 — SET UP MONITOR MODE
# =============================================================================

print_banner("STEP 1 — Set Up Monitor Mode")

# Show the user which wireless interfaces we can see
available_interfaces = get_wireless_interfaces()
if available_interfaces:
    print(f"\n  Wireless interfaces found on this machine: {', '.join(available_interfaces)}")

# Ask which interface to use
DEFAULT_INTERFACE = "wlan0"
while True:
    typed = input(f"\n  Which interface do you want to use? (press Enter for '{DEFAULT_INTERFACE}'): ").strip()
    chosen_interface = typed or DEFAULT_INTERFACE

    if interface_exists(chosen_interface):
        print(f"  [OK] Found interface '{chosen_interface}'.")
        break

    print(f"  [ERROR] No interface called '{chosen_interface}' was found.")
    if not ask_yes_no("Try a different name?"):
        sys.exit(1)

# Kill programs that might block monitor mode (like NetworkManager)
print_section("Stop Programs That Block Monitor Mode")
if ask_yes_no("Run 'airmon-ng check kill' to stop conflicting programs?"):
    run_command(["sudo", "airmon-ng", "check", "kill"])

# Start monitor mode on the chosen interface
print_section("Enable Monitor Mode")
if ask_yes_no(f"Run 'airmon-ng start {chosen_interface}' to enable monitor mode?"):
    result = run_command(["sudo", "airmon-ng", "start", chosen_interface])
    if result:
        # airmon-ng often renames the interface (e.g. wlan0 → wlan0mon)
        match = re.search(r"(wlan\d+mon|mon\d+)", result.stdout)
        if match and interface_exists(match.group(1)):
            chosen_interface = match.group(1)
            print(f"  [OK] Interface was renamed to '{chosen_interface}' (this is normal).")

# Warn the user if monitor mode still isn't active
if not interface_is_in_monitor_mode(chosen_interface):
    print(f"\n  [WARNING] '{chosen_interface}' does not appear to be in monitor mode.")
    print("  The detector may not work correctly without monitor mode.")
    if not ask_yes_no("Continue anyway?"):
        sys.exit(1)

print(f"\n  Using interface: {chosen_interface}")


# =============================================================================
#   STEP 2 — CHOOSE WHICH ATTACKS TO WATCH FOR
# =============================================================================

print_banner("STEP 2 — Choose Attacks to Monitor")

print("  TESTED (recommended — these work reliably):")
for number, label in TESTED_ATTACKS.items():
    print(f"    [{number:2}] {label}")

print("\n  BETA (experimental — may produce false positives):")
for number, label in BETA_ATTACKS.items():
    print(f"    [{number:2}] {label}")

print()
print("  Options:")
print("    T  = Tested attacks only (safest choice)")
print("    A  = All attacks (tested + beta)")
print("    Or type specific numbers separated by commas, e.g.: 1,4,6")

while True:
    raw_input = input("\n  Your choice: ").strip().upper()

    if raw_input == "T":
        selected_attacks = list(TESTED_ATTACKS.keys())
        break

    if raw_input == "A":
        selected_attacks = sorted(TESTED_ATTACKS.keys() | BETA_ATTACKS.keys())
        break

    # Parse comma-separated numbers
    parsed = [
        int(x) for x in raw_input.split(",")
        if x.strip().isdigit() and int(x) in ATTACK_SHORT_NAMES
    ]
    if parsed:
        selected_attacks = parsed
        break

    print("  [ERROR] That wasn't a valid choice. Try 'T', 'A', or numbers like '1,4'.")

print(f"\n  You chose: {', '.join(ATTACK_SHORT_NAMES[n] for n in selected_attacks)}")


# =============================================================================
#   STEP 3 — CHOOSE A NAME FOR THE DETECTOR SCRIPT
# =============================================================================

print_banner("STEP 3 — Name Your Detector Script")

print("  The baseline learner will save a ready-to-run detector script.")
print("  Give it a name so you can find it easily later.")

while True:
    typed_name = input("\n  Filename for the detector (e.g. my_detector): ").strip()
    if not typed_name:
        print("  [ERROR] Please enter a name.")
        continue

    output_filename = make_safe_filename(typed_name)
    print(f"  Will save as: {output_filename}")

    if os.path.exists(output_filename):
        if not ask_yes_no("That file already exists. Overwrite it?"):
            continue

    if ask_yes_no("Confirm this filename?"):
        break


# =============================================================================
#   STEP 4 — COLLECT BASELINE (NORMAL) TRAFFIC
#   The tool needs to see what normal traffic looks like so it can
#   tell the difference between normal activity and an attack.
# =============================================================================

print_banner("STEP 4 — Collect Normal Traffic (Baseline)")

print("""
  The detector learns by seeing "normal" traffic on your network.
  You have two options:

    [1] Load a saved capture file (.pcap) — best for lab / testing
    [2] Capture live traffic right now   — best for real networks

  IMPORTANT: Option 2 must be run with NO attacks happening.
             The tool is learning what safe traffic looks like.
""")

while True:
    mode = input("  Enter 1 or 2: ").strip()
    if mode in ("1", "2"):
        break
    print("  [ERROR] Please enter 1 or 2.")

# These counters track how many times each event type is seen during baseline
packet_counts    = defaultdict(int)   # total count per attack type
probe_per_mac    = defaultdict(int)   # probe requests per device
arp_per_mac      = defaultdict(int)   # ARP frames per device
frag_per_mac     = defaultdict(int)   # fragmented frames per device
bssid_channels   = defaultdict(set)   # channels seen for each access point
baseline_minutes = 0.0

# RSSI baseline — record the normal signal strength for every device we see.
# During an attack, the detector compares live signal against this baseline
# to tell whether the attacker has moved closer than a known device normally is.
rssi_baseline_per_mac = defaultdict(list)   # mac -> list of RSSI readings


def count_packet(packet):
    """
    Inspect one wireless packet and count it under the right attack category.
    Also records the RSSI (signal strength) for each device seen.
    This is called for every packet during the baseline phase.
    """
    try:
        if not packet.haslayer(Dot11):
            return  # Not a Wi-Fi packet — skip it

        dot11   = packet[Dot11]
        ptype   = dot11.type       # 0 = management, 1 = control, 2 = data
        subtype = dot11.subtype
        src_mac = dot11.addr2 or ""
        bssid   = dot11.addr3 or dot11.addr1 or ""

        # Record RSSI for this device to build a "normal signal strength" reference
        rssi = extract_rssi(packet)
        if rssi is not None and src_mac:
            rssi_baseline_per_mac[src_mac].append(rssi)

        # Attack 1 — Deauthentication (someone is forcibly disconnecting devices)
        if 1 in selected_attacks and ptype == 0 and subtype == 12:
            packet_counts[1] += 1

        # Attack 2 — Beacon Flood (fake access points spamming the airwaves)
        if 2 in selected_attacks and ptype == 0 and subtype == 8:
            packet_counts[2] += 1

        # Attack 3 — Probe Request Flood (device scanning for networks too fast)
        if 3 in selected_attacks and ptype == 0 and subtype == 4:
            packet_counts[3] += 1
            if src_mac:
                probe_per_mac[src_mac] += 1

        # Attack 4 — Auth/Assoc Flood (overwhelming the access point with join requests)
        if 4 in selected_attacks and ptype == 0 and subtype in (0, 2, 11):
            packet_counts[4] += 1

        # Attack 5 — Evil Twin (an access point showing up on multiple channels)
        if 5 in selected_attacks and ptype == 0 and subtype == 8 and bssid:
            if packet.haslayer(RadioTap):
                channel = packet[RadioTap].Channel
                if channel:
                    bssid_channels[bssid].add(channel)
                    if len(bssid_channels[bssid]) > 1:
                        packet_counts[5] += 1

        # Attack 6 — EAPOL / PMKID (someone capturing the Wi-Fi login handshake)
        if 6 in selected_attacks and packet.haslayer(EAPOL):
            packet_counts[6] += 1

        # Attack 7 — CTS/RTS Flood (jamming the channel with control frames)
        if 7 in selected_attacks and ptype == 1 and subtype in (11, 12):
            packet_counts[7] += 1

        # Attack 8 — TKIP MIC Failure (signs of the old TKIP encryption being attacked)
        if 8 in selected_attacks and ptype == 2 and (getattr(dot11, "FCfield", 0) & 0x40):
            packet_counts[8] += 1

        # Attack 9 — Null Function / Power-Save DoS (putting devices into sleep mode forcibly)
        if 9 in selected_attacks and ptype == 2 and subtype in (4, 12):
            packet_counts[9] += 1

        # Attack 10 — ARP Replay (replaying ARP packets to generate traffic)
        if 10 in selected_attacks and packet.haslayer(ARP):
            packet_counts[10] += 1
            if src_mac:
                arp_per_mac[src_mac] += 1

        # Attack 11 — Fragmentation Attack (sending broken-up packets to confuse devices)
        if 11 in selected_attacks and ptype == 2 and (getattr(dot11, "FCfield", 0) & 0x04):
            packet_counts[11] += 1
            if src_mac:
                frag_per_mac[src_mac] += 1

    except Exception:
        pass  # Skip any packet that causes an unexpected error


# ── Option 1: Load from a saved capture file ──────────────────────────────────
if mode == "1":
    while True:
        pcap_path = input("\n  Full path to your normal/clean capture file: ").strip()

        if not os.path.isfile(pcap_path):
            print("  [ERROR] File not found. Check the path and try again.")
            if not ask_yes_no("Try again?"):
                sys.exit(1)
            continue

        print("  Loading packets from file...")
        packets = rdpcap(pcap_path)

        # Work out how long the capture ran so averages are accurate
        try:
            if len(packets) > 1:
                first_time = float(packets[0].time)
                last_time  = float(packets[-1].time)
                duration_seconds = last_time - first_time
                baseline_minutes = max(duration_seconds / 60.0, 0.5)
                print(f"  [OK] Capture duration: {baseline_minutes:.2f} minutes")
            else:
                baseline_minutes = 15.0
                print("  [OK] Could not calculate duration — using 15 minutes as a default.")
        except Exception:
            baseline_minutes = 15.0

        # Count every packet
        for pkt in packets:
            count_packet(pkt)

        print(f"  [OK] Processed {len(packets):,} packets.")
        break

# ── Option 2: Capture live traffic ────────────────────────────────────────────
else:
    channel = input("\n  Which Wi-Fi channel should we monitor? ").strip()
    run_command(["sudo", "iwconfig", chosen_interface, "channel", channel])

    while True:
        raw_duration = input("  How many minutes to capture? (10–20 recommended): ").strip()
        if raw_duration.isdigit() and int(raw_duration) > 0:
            baseline_minutes = int(raw_duration)
            break
        print("  [ERROR] Please enter a whole number, e.g. 10 or 15.")

    print(f"\n  Capturing normal traffic for {int(baseline_minutes)} minutes...")
    print("  Make sure no attacks are running during this time!\n")
    sniff(iface=chosen_interface, prn=count_packet, timeout=baseline_minutes * 60, store=0)

# Guard against zero duration (would cause division by zero)
if baseline_minutes == 0:
    baseline_minutes = 1

# Average the RSSI readings per device to get a "normal signal" reference
rssi_normal_avg = {}
for mac, readings in rssi_baseline_per_mac.items():
    if readings:
        rssi_normal_avg[mac] = sum(readings) / len(readings)


# =============================================================================
#   STEP 5 — CALCULATE THRESHOLDS
#   A threshold is the packet-count above which the detector cries "attack!"
#   We calculate: (average packets per minute) × (your chosen multiplier).
#   A lower multiplier catches attacks earlier but may give more false alarms.
# =============================================================================

print_banner("STEP 5 — Review Baseline Results and Set Sensitivity")

print("  The multiplier controls how sensitive the detector is.")
print("  Lower number = catches attacks sooner, but more false alarms.")
print("  Higher number = fewer false alarms, but may miss subtle attacks.")
print("  Recommended starting point: 3.0\n")

while True:
    raw_multiplier = input("  Enter multiplier (press Enter for 3.0): ").strip()
    if not raw_multiplier:
        multiplier = 3.0
        break
    try:
        multiplier = float(raw_multiplier)
        if multiplier > 0.5:
            break
        print("  [ERROR] Multiplier must be greater than 0.5.")
    except ValueError:
        print("  [ERROR] Please enter a number like 2.5 or 3.0.")

print(f"\n  Using multiplier: {multiplier}×\n")

# Calculate per-minute averages and thresholds for each selected attack
averages   = {}
thresholds = {}
for attack_id in selected_attacks:
    avg = packet_counts[attack_id] / baseline_minutes
    averages[attack_id]   = avg
    thresholds[attack_id] = avg * multiplier

# Per-device averages for attacks that track individual devices
probe_avg = (
    (sum(probe_per_mac.values()) / len(probe_per_mac) / baseline_minutes)
    if probe_per_mac else 0.0
)
arp_avg = (
    (sum(arp_per_mac.values()) / len(arp_per_mac) / baseline_minutes)
    if arp_per_mac else 0.0
)
frag_avg = (
    (sum(frag_per_mac.values()) / len(frag_per_mac) / baseline_minutes)
    if frag_per_mac else 0.0
)

# Print a summary table
print("  Attack Type                              Avg/min   Threshold/min")
print("  " + "─" * 68)
for attack_id in selected_attacks:
    name  = ATTACK_SHORT_NAMES[attack_id]
    badge = " [BETA]" if attack_id in BETA_ATTACKS else "       "
    print(
        f"  [{attack_id:2}] {name + badge:<38} "
        f"{averages[attack_id]:>8.2f}   {thresholds[attack_id]:>8.2f}"
    )

print(
    "\n  The detector will alert when packet counts exceed the threshold "
    "in a 20-second window."
)

# Show RSSI summary if we managed to capture signal data
if rssi_normal_avg:
    print(f"\n  RSSI baseline recorded for {len(rssi_normal_avg)} known device(s).")
    print("  During an attack the detector will compare live signal against this")
    print("  baseline to estimate where the attacking device is physically located.")


# =============================================================================
#   STEP 6 — GENERATE THE DETECTOR SCRIPT
#   We now write a self-contained Python script that:
#   - Captures traffic in 20-second windows
#   - Compares counts to the thresholds learned above
#   - When an attack is detected, reads RSSI to estimate attacker location
#   - Shows signal strength, distance estimate, and movement trend
# =============================================================================

print_banner("STEP 6 — Writing the Detector Script")

# Build the threshold block that goes inside the generated script
threshold_lines = "\n".join(
    f"    {aid:2d}: {thresholds[aid]:.4f},  # {ATTACK_SHORT_NAMES[aid]}"
    for aid in selected_attacks
)

# Build the known-device RSSI baseline dictionary for the generated script
rssi_baseline_lines = ",\n".join(
    f'    "{mac}": {avg:.1f}'
    for mac, avg in rssi_normal_avg.items()
)

timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

detector_code = f'''#!/usr/bin/env python3
# =============================================================================
#   Wireless Attack Detector — Auto-generated
#   Created    : {timestamp}
#   Interface  : {chosen_interface}
#
#   How to run : sudo python3 {output_filename}
#
#   How it works:
#     Every 20 seconds this script counts specific types of Wi-Fi packets.
#     If any count exceeds the baseline threshold, it prints an alert.
#     When an attack is detected, it also reads the RSSI (signal strength)
#     from the attacking device's packets and tells you:
#       - How strong their signal is in dBm
#       - A plain-English estimate of how far away they are
#       - Whether their signal is getting stronger (they are moving closer)
# =============================================================================

import sys
import time
from collections import defaultdict
from scapy.all import sniff, Dot11, RadioTap, EAPOL, ARP

# ── Settings ──────────────────────────────────────────────────────────────────
INTERFACE   = "{chosen_interface}"   # Interface to listen on (must be in monitor mode)
WINDOW_SECS = 20                     # Seconds per detection window

# Short names for each attack type (used in alert messages)
ATTACK_NAMES = {ATTACK_SHORT_NAMES}

# Packet-count limits per 20-second window.
# Anything above these numbers triggers an alert.
THRESHOLDS = {{
{threshold_lines}
}}

# Per-device limits for attacks that track individual MAC addresses
PROBE_LIMIT_PER_DEVICE = {probe_avg * multiplier:.4f}
ARP_LIMIT_PER_DEVICE   = {arp_avg   * multiplier:.4f}
FRAG_LIMIT_PER_DEVICE  = {frag_avg  * multiplier:.4f}

SELECTED_ATTACKS = {selected_attacks}

# Normal signal strength (RSSI) for devices seen during baseline learning.
# If an attacker shows up much stronger than a device was normally,
# it means they are physically closer than a legitimate device would be.
KNOWN_DEVICE_RSSI_BASELINE = {{
{rssi_baseline_lines}
}}

# ── Start-up message ──────────────────────────────────────────────────────────
print("=" * 70)
print("  Wireless Attack Detector — Real-Time Monitor")
print(f"  Listening on  : {{INTERFACE}}")
print(f"  Watching for  : {{len(SELECTED_ATTACKS)}} attack type(s)")
print(f"  Window size   : {{WINDOW_SECS}} seconds")
print(f"  Known devices : {{len(KNOWN_DEVICE_RSSI_BASELINE)}} (RSSI baseline loaded)")
print("=" * 70)
print("  Press Ctrl+C at any time to stop.\\n")


# =============================================================================
#   RSSI HELPER FUNCTIONS
#   RSSI = Received Signal Strength Indicator
#   It is a negative number (dBm). Closer to zero = stronger signal = device is near.
# =============================================================================

def extract_rssi(packet) -> int | None:
    """
    Pull the signal strength (RSSI) value out of the packet's RadioTap header.
    RadioTap is the radio-layer wrapper your Wi-Fi card puts around every packet.
    Returns a negative integer like -65, or None if the value is not available.
    """
    try:
        if packet.haslayer(RadioTap):
            rt = packet[RadioTap]
            if hasattr(rt, "dBm_AntSignal") and rt.dBm_AntSignal is not None:
                return int(rt.dBm_AntSignal)
    except Exception:
        pass
    return None


def rssi_to_distance_label(rssi: int) -> str:
    """
    Convert an RSSI value into a plain-English distance estimate.
    Walls and other obstacles will reduce accuracy, but this gives
    a useful starting point for physically locating a device.
    """
    if rssi >= -50:
        return "Very close  (likely under 5 metres — same room as you)"
    elif rssi >= -60:
        return "Close       (roughly 5–15 metres — probably the next room)"
    elif rssi >= -70:
        return "Medium      (roughly 15–30 metres — same building)"
    elif rssi >= -80:
        return "Far         (roughly 30–60 metres — different floor or just outside)"
    else:
        return "Very far    (60+ metres — at the edge of Wi-Fi range)"


def rssi_to_signal_bar(rssi: int) -> str:
    """Show signal strength as a simple visual bar in the terminal."""
    if rssi >= -50:
        return "[████████] Excellent"
    elif rssi >= -60:
        return "[██████░░] Good"
    elif rssi >= -70:
        return "[████░░░░] Fair"
    elif rssi >= -80:
        return "[██░░░░░░] Weak"
    else:
        return "[░░░░░░░░] Very Weak"


def describe_attacker_location(mac: str, current_rssi: int) -> list:
    """
    Build a list of plain-English lines describing the attacker's location.
    If we have a baseline RSSI for this MAC from the learning phase we compare
    current signal against normal — a much stronger signal means they moved closer.
    """
    lines = []
    lines.append(f"    Signal strength : {{current_rssi}} dBm  {{rssi_to_signal_bar(current_rssi)}}")
    lines.append(f"    Distance hint   : {{rssi_to_distance_label(current_rssi)}}")

    if mac in KNOWN_DEVICE_RSSI_BASELINE:
        normal_rssi = KNOWN_DEVICE_RSSI_BASELINE[mac]
        difference  = current_rssi - normal_rssi   # positive = signal is stronger now

        if difference >= 15:
            lines.append(
                f"    Movement alert  : Signal is {{difference}} dBm STRONGER than when"
                f" we learned this device (baseline: {{normal_rssi:.0f}} dBm)."
                f" The attacker has moved much closer!"
            )
        elif difference <= -15:
            lines.append(
                f"    Movement note   : Signal is {{abs(difference)}} dBm weaker than baseline"
                f" ({{normal_rssi:.0f}} dBm). The attacker may be moving away."
            )
        else:
            lines.append(
                f"    Movement status : Signal is close to baseline ({{normal_rssi:.0f}} dBm)."
                f" Attacker position has not changed significantly."
            )
    else:
        lines.append(
            "    Known device    : This MAC was not seen during baseline learning."
            " No normal signal to compare against — this may be a spoofed or new device."
        )

    return lines


# =============================================================================
#   MAIN DETECTION LOOP
#   Runs forever, checking traffic every 20 seconds.
# =============================================================================

def run_detector():
    # Rolling RSSI history per device — we keep the last 5 window averages.
    # This lets us spot a trend: if signal keeps getting stronger window after
    # window, the attacker is steadily moving closer.
    rssi_history = defaultdict(list)

    while True:
        # Reset all counters at the start of each 20-second window
        counts      = defaultdict(int)
        probe_mac   = defaultdict(int)
        arp_mac     = defaultdict(int)
        frag_mac    = defaultdict(int)
        bssid_chans = defaultdict(set)

        # Collect every RSSI reading per device during this window.
        # We average them at the end for a stable location estimate.
        rssi_readings = defaultdict(list)

        def inspect_packet(pkt):
            """Read one packet, update attack counters, and record signal strength."""
            try:
                if not pkt.haslayer(Dot11):
                    return

                dot11   = pkt[Dot11]
                ptype   = dot11.type
                subtype = dot11.subtype
                src_mac = dot11.addr2 or ""
                bssid   = dot11.addr3 or dot11.addr1 or ""

                # Always record signal strength for every device we can hear
                rssi = extract_rssi(pkt)
                if rssi is not None and src_mac:
                    rssi_readings[src_mac].append(rssi)

                # Deauthentication frames
                if 1 in SELECTED_ATTACKS and ptype == 0 and subtype == 12:
                    counts[1] += 1

                # Beacon frames (used in beacon floods)
                if 2 in SELECTED_ATTACKS and ptype == 0 and subtype == 8:
                    counts[2] += 1

                # Probe request frames
                if 3 in SELECTED_ATTACKS and ptype == 0 and subtype == 4:
                    counts[3] += 1
                    if src_mac:
                        probe_mac[src_mac] += 1

                # Authentication and association frames
                if 4 in SELECTED_ATTACKS and ptype == 0 and subtype in (0, 2, 11):
                    counts[4] += 1

                # Evil Twin — same access point BSSID seen on more than one channel
                if 5 in SELECTED_ATTACKS and ptype == 0 and subtype == 8 and bssid:
                    if pkt.haslayer(RadioTap):
                        ch = pkt[RadioTap].Channel
                        if ch:
                            bssid_chans[bssid].add(ch)
                            if len(bssid_chans[bssid]) > 1:
                                counts[5] += 1

                # EAPOL frames (Wi-Fi handshake capture attempts)
                if 6 in SELECTED_ATTACKS and pkt.haslayer(EAPOL):
                    counts[6] += 1

                # CTS / RTS control frames
                if 7 in SELECTED_ATTACKS and ptype == 1 and subtype in (11, 12):
                    counts[7] += 1

                # TKIP MIC failure flag set in data frame header
                if 8 in SELECTED_ATTACKS and ptype == 2 and (getattr(dot11, "FCfield", 0) & 0x40):
                    counts[8] += 1

                # Null function / power-save management frames
                if 9 in SELECTED_ATTACKS and ptype == 2 and subtype in (4, 12):
                    counts[9] += 1

                # ARP frames (used in replay attacks)
                if 10 in SELECTED_ATTACKS and pkt.haslayer(ARP):
                    counts[10] += 1
                    if src_mac:
                        arp_mac[src_mac] += 1

                # Fragmented data frames
                if 11 in SELECTED_ATTACKS and ptype == 2 and (getattr(dot11, "FCfield", 0) & 0x04):
                    counts[11] += 1
                    if src_mac:
                        frag_mac[src_mac] += 1

            except Exception:
                pass  # Skip any packet that causes an unexpected error

        # ── Capture traffic for one 20-second window ───────────────────────
        try:
            sniff(iface=INTERFACE, prn=inspect_packet, timeout=WINDOW_SECS, store=0)
        except PermissionError:
            print("[FATAL] Permission denied. Run this script with: sudo python3 {output_filename}")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\\nDetector stopped by user.")
            sys.exit(0)
        except Exception:
            time.sleep(5)
            continue

        # ── Average the RSSI readings collected this window ────────────────
        # Averaging smooths out single-packet spikes and gives a more
        # reliable estimate of where each device actually is.
        avg_rssi_this_window = {{
            mac: sum(readings) / len(readings)
            for mac, readings in rssi_readings.items()
            if readings
        }}

        # Add this window's average to each device's rolling RSSI history
        for mac, avg in avg_rssi_this_window.items():
            rssi_history[mac].append(avg)
            if len(rssi_history[mac]) > 5:
                rssi_history[mac].pop(0)   # Drop the oldest reading, keep last 5

        # ── Print the detection report for this window ─────────────────────
        window_time       = time.strftime("%H:%M:%S")
        triggered_attacks = []
        attacking_macs    = set()   # MACs that were flagged by per-device checks

        print(f"\\n[{{window_time}}] ── 20-Second Window Report ──")
        print(f"  {{\'Attack Type\':<40}} {{\'Packets\':>8}} {{\'Limit\':>8}}  Status")
        print("  " + "─" * 68)

        for attack_id in SELECTED_ATTACKS:
            name   = ATTACK_NAMES.get(attack_id, f"Attack {{attack_id}}")
            count  = counts[attack_id]
            limit  = THRESHOLDS.get(attack_id, 0.0)
            status = "*** ALERT ***" if count > limit else "OK"

            print(f"  {{name:<40}} {{count:>8}} {{limit:>8.1f}}  {{status}}")

            if count > limit:
                triggered_attacks.append(attack_id)

        # ── Per-device threshold checks ────────────────────────────────────
        for mac, n in probe_mac.items():
            if PROBE_LIMIT_PER_DEVICE > 0 and n > PROBE_LIMIT_PER_DEVICE:
                print(f"  [!] Probe flood from {{mac}} — {{n}} probe requests in 20 seconds")
                if 3 not in triggered_attacks:
                    triggered_attacks.append(3)
                attacking_macs.add(mac)

        for mac, n in arp_mac.items():
            if ARP_LIMIT_PER_DEVICE > 0 and n > ARP_LIMIT_PER_DEVICE:
                print(f"  [!] ARP replay from {{mac}} — {{n}} frames in 20 seconds")
                if 10 not in triggered_attacks:
                    triggered_attacks.append(10)
                attacking_macs.add(mac)

        for mac, n in frag_mac.items():
            if FRAG_LIMIT_PER_DEVICE > 0 and n > FRAG_LIMIT_PER_DEVICE:
                print(f"  [!] Fragmentation attack from {{mac}} — {{n}} fragments in 20 seconds")
                if 11 not in triggered_attacks:
                    triggered_attacks.append(11)
                attacking_macs.add(mac)

        # ── Final verdict + RSSI location report ──────────────────────────
        if triggered_attacks:
            attack_label = ", ".join(ATTACK_NAMES.get(a, str(a)) for a in triggered_attacks)
            print(f"\\n  !!! ATTACK DETECTED: {{attack_label}}")
            print("  !!! Please investigate your network immediately.")

            # ── Work out which MACs to report location for ─────────────────
            # For per-device attacks (probe, ARP, frag) we already have the MAC.
            # For global attacks (deauth, beacon flood etc.) we can't pinpoint
            # a single MAC from just the counter — so we fall back to highlighting
            # the device with the strongest signal, since attackers generally
            # need to be physically close to be effective.
            suspect_macs = set(attacking_macs)

            if triggered_attacks and not suspect_macs:
                if avg_rssi_this_window:
                    closest_mac = max(avg_rssi_this_window, key=avg_rssi_this_window.get)
                    suspect_macs.add(closest_mac)

            # ── Print RSSI location block ──────────────────────────────────
            if suspect_macs:
                print("\\n  ── Attacker Location Estimate (RSSI) ──────────────────────────────")
                print("  RSSI = Received Signal Strength. Closer to 0 dBm means the device")
                print("  is physically near you. Use this to help locate the attacker.\\n")

                for mac in suspect_macs:
                    current_avg_rssi = avg_rssi_this_window.get(mac)
                    print(f"  Suspected device : {{mac}}")

                    if current_avg_rssi is not None:
                        rssi_int = int(current_avg_rssi)

                        # Print signal strength and distance estimate
                        for line in describe_attacker_location(mac, rssi_int):
                            print(line)

                        # Print trend (is the signal getting stronger over time?)
                        history = rssi_history.get(mac, [])
                        if len(history) >= 3:
                            trend = history[-1] - history[0]   # positive = getting stronger
                            if trend >= 10:
                                print(
                                    f"    Trend warning   : Signal has risen {{trend:.0f}} dBm over"
                                    f" the last {{len(history)}} windows — the attacker is moving closer!"
                                )
                            elif trend <= -10:
                                print(
                                    f"    Trend note      : Signal has dropped {{abs(trend):.0f}} dBm"
                                    f" over {{len(history)}} windows — the attacker may be leaving."
                                )
                            else:
                                print("    Trend           : Signal is steady — attacker has not moved.")
                        else:
                            print("    Trend           : Not enough windows yet to show movement trend.")

                    else:
                        print("    RSSI            : No signal data was captured for this device this window.")
                        print("    This can happen if the device is using very short bursts of traffic.")

                    print()   # Blank line between devices

            else:
                print("\\n  Location estimate: No specific device could be identified.")
                print("  This is common with attacks that randomise or spoof their MAC address.")

        else:
            print("\\n  All clear — traffic looks normal.")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        run_detector()
    except KeyboardInterrupt:
        print("\\nDetector stopped.")
'''

# ── Save the file and make it executable ─────────────────────────────────────
with open(output_filename, "w") as f:
    f.write(detector_code)
os.chmod(output_filename, 0o755)

print(f"\n  [OK] Detector script saved as: {output_filename}")
print(f"\n  To start the detector, run:")
print(f"      sudo python3 {output_filename}")
print("\n  When an attack is detected, the detector will now also show:")
print("    • The attacking device's MAC address")
print("    • Current signal strength in dBm and a visual bar")
print("    • A plain-English distance estimate (e.g. 'Close — roughly 5–15 metres')")
print("    • Whether the signal has changed vs the device's normal baseline")
print("    • A movement trend — is the attacker getting closer over time?")
