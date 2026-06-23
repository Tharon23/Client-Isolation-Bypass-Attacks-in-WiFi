#!/usr/bin/env python3
"""
topologia bazowa labu pmf bypass (Mininet-WiFi v2.0)
1 ap + 3 stacje, wpa2-psk z ccmp, pmf required (ieee80211w=2), client isolation (ap_isolate=1)
"""

import argparse
import os
import sys
import time

from mn_wifi.net import Mininet_wifi
from mn_wifi.node import Station, OVSKernelAP
from mn_wifi.cli import CLI
from mn_wifi.link import wmediumd, mesh
from mininet.log import setLogLevel, info


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOSTAPD_CONF = os.path.join(BASE_DIR, "configs", "hostapd.conf")
WPA_CONF = os.path.join(BASE_DIR, "configs", "wpa_supplicant.conf")


def build_topo():
    """buduje topologie labu: 1 ap + 3 stacje"""
    net = Mininet_wifi()

    info("*** Creating nodes\n")

    # access point z hostapd config (pmf + client isolation)
    ap1 = net.addAccessPoint(
        "ap1",
        ssid="PMF_Lab_Secure",
        mode="g",
        channel="6",
        position="50,50,0",
        hostapd_params=["-f", HOSTAPD_CONF],
        failMode="standalone",
    )

    # trzy stacje klienckie z wpa_supplicant config
    sta1 = net.addStation(
        "sta1",
        position="30,50,0",
        wpas_params=["-c", WPA_CONF],
    )
    sta2 = net.addStation(
        "sta2",
        position="70,50,0",
        wpas_params=["-c", WPA_CONF],
    )
    sta3 = net.addStation(
        "sta3",
        position="50,80,0",
        wpas_params=["-c", WPA_CONF],
    )

    info("*** Configuring propagation model\n")
    net.setPropagationModel(model="logDistance", exp=3.5)

    info("*** Configuring nodes\n")
    net.configureNodes()

    info("*** Creating links\n")
    net.addLink(ap1, sta1)
    net.addLink(ap1, sta2)
    net.addLink(ap1, sta3)

    info("*** Plotting graph\n")
    net.plotGraph(max_x=100, max_y=100)

    return net, ap1, sta1, sta2, sta3


def run_cli(net):
    """odpala interaktywne cli Mininet do recznego testowania"""
    CLI(net)


def run_headless(net, ap1, sta1, sta2, sta3):
    """odpala bez interakcji z weryfikacja bazowa, potem konczy"""
    info("\n*** Starting network\n")
    net.start()

    info("\n*** Waiting for association...\n")
    time.sleep(10)

    for sta in [sta1, sta2, sta3]:
        info(f"  {sta.name}: ", end="")
        result = sta.cmd("iw dev {}-wlan0 link".format(sta.name))
        if "Not connected" in result:
            info(f"NOT CONNECTED\n")
        else:
            info(f"associated\n")

    info("\n*** Network running. Use CLI mode for interactive testing.\n")
    info("    sudo python3 lab_topology.py --cli\n")

    net.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PMF Bypass Lab Topology")
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Launch Mininet CLI after topology start",
    )
    parser.add_argument(
        "--kismet",
        action="store_true",
        help="Start Kismet on monitor interface (requires kismet installed)",
    )
    args = parser.parse_args()

    setLogLevel("info")

    net, ap1, sta1, sta2, sta3 = build_topo()

    if args.cli:
        net.start()
        info("\n*** Waiting for association...\n")
        time.sleep(10)

        for sta in [sta1, sta2, sta3]:
            info(f"  {sta.name} status: ")
            result = sta.cmd("iw dev {}-wlan0 link".format(sta.name))
            info(result.strip()[:80] + "\n")

        # opcjonalnie: kismet na interfejsie monitor ap1
        if args.kismet:
            info("*** Starting Kismet on ap1 monitor interface\n")
            ap1.cmd("kismet -c ap1-mp1 &")
            info("    Kismet running in background (PID check via 'ps aux | grep kismet')\n")

        CLI(net)
        net.stop()
    else:
        run_headless(net, ap1, sta1, sta2, sta3)
