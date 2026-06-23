#!/usr/bin/env python3
"""
BBSK Projekt - Topologia Mininet-wifi
Atak: MAC Spoofing + Association Hijacking (Ominięcie Client Isolation)

Topologia:
    sta1 (ofiara)  sta2 (atakujący)
         \              /
          ---- ap1 ----
                |
               h1 (serwer)

Użycie:
    sudo python3 ~/bbsk-projekt/topology.py
"""

import os
import sys
from mininet.log import setLogLevel, info
from mininet.node import Controller
from mn_wifi.net import Mininet_wifi
from mn_wifi.cli import CLI


def topology():
    setLogLevel('info')

    info("*** Tworzenie sieci Mininet-wifi\n")
    net = Mininet_wifi(controller=Controller)

    info("*** Dodawanie kontrolera\n")
    c0 = net.addController('c0')

    info("*** Dodawanie stacji (klientów Wi-Fi)\n")
    sta1 = net.addStation('sta1', ip='10.0.0.1/24', position='20,50,0')
    sta2 = net.addStation('sta2', ip='10.0.0.2/24', position='80,50,0')

    info("*** Dodawanie Access Pointa z Client Isolation\n")
    ap1 = net.addAccessPoint(
        'ap1',
        ssid='testnet',
        mode='g',
        channel='6',
        passwd='password123',
        encrypt='wpa2',
        ieee80211w='0',
        client_isolation=True,
        position='50,50,0',
        failMode='standalone'
    )

    info("*** Dodawanie hosta (serwer/cel ruchu)\n")
    h1 = net.addHost('h1', ip='10.0.0.100/24')

    info("*** Tworzenie linku h1 <-> ap1 (przed build)\n")
    net.addLink(h1, ap1)

    info("*** Budowanie sieci\n")
    net.configureWifiNodes()
    net.build()

    info("*** Uruchamianie kontrolera i AP\n")
    c0.start()
    ap1.start([c0])

    import time
    import subprocess as _sp
    time.sleep(3)

    info("*** Konfiguracja OVS bridge\n")
    ap_wlan = ap1.params['wlan'][0]


    _sp.run('ovs-vsctl del-port ap1 ap1-wlan2 2>/dev/null', shell=True)
    _sp.run('ovs-vsctl del-port ap1 h1-eth0   2>/dev/null', shell=True)
    _sp.run(f'ovs-vsctl add-port ap1 {ap_wlan} 2>/dev/null', shell=True)

    info("*** Konfiguracja IP\n")
    h1.cmd('ip addr flush dev h1-eth0')
    h1.cmd('ip addr add 10.0.0.100/24 dev h1-eth0')
    h1.cmd('ip link set h1-eth0 up')

    sta1.cmd('ip addr flush dev sta1-wlan0')
    sta1.cmd('ip addr add 10.0.0.1/24 dev sta1-wlan0')
    sta1.cmd('ip link set sta1-wlan0 up')

    sta2.cmd('ip addr flush dev sta2-wlan0')
    sta2.cmd('ip addr add 10.0.0.2/24 dev sta2-wlan0')
    sta2.cmd('ip link set sta2-wlan0 up')

    time.sleep(2)
    info(f"*** Bridge ports: {ap1.cmd('ovs-vsctl list-ports ap1')}\n")

    victim_mac  = sta1.wintfs[0].mac if hasattr(sta1, 'wintfs') and sta1.wintfs else sta1.defaultIntf().mac
    att_mac     = sta2.wintfs[0].mac if hasattr(sta2, 'wintfs') and sta2.wintfs else sta2.defaultIntf().mac
    ap_mac      = ap1.wintfs[0].mac  if hasattr(ap1,  'wintfs') and ap1.wintfs  else 'N/A'

    info("\n" + "="*60 + "\n")
    info("*** TOPOLOGIA GOTOWA\n")
    info("="*60 + "\n")
    info("Stacje:\n")
    info(f"  sta1 (OFIARA)     IP: 10.0.0.1    MAC: {victim_mac}\n")
    info(f"  sta2 (ATAKUJĄCY)  IP: 10.0.0.2    MAC: {att_mac}\n")
    info("  h1   (SERWER)     IP: 10.0.0.100\n")
    info("  ap1  (AP)         SSID: testnet    Izolacja: WŁĄCZONA\n\n")
    info("BASELINE TEST (izolacja powinna blokować):\n")
    info("  mininet-wifi> sta1 ping -c 3 10.0.0.2    <- powinno FAILOWAĆ\n")
    info("  mininet-wifi> sta1 ping -c 3 10.0.0.100  <- powinno DZIAŁAĆ\n\n")
    info("ATAK:\n")
    info("  mininet-wifi> sta2 python3 /home/kali/bbsk-projekt/attack.py\n")
    info("="*60 + "\n\n")

    os.makedirs('/tmp', exist_ok=True)
    with open('/tmp/bbsk_config.txt', 'w') as f:
        f.write(f"VICTIM_MAC={victim_mac}\n")
        f.write(f"VICTIM_IP=10.0.0.1\n")
        f.write(f"AP_MAC={ap_mac}\n")
        f.write(f"ATTACKER_IFACE=sta2-wlan0\n")
        f.write(f"VICTIM_IFACE=sta1-wlan0\n")
        f.write(f"H1_PID={h1.pid}\n")
        f.write("H1_IFACE=h1-eth0\n")
        f.write("H1_IP=10.0.0.100\n")
    info(f"*** Konfiguracja zapisana: /tmp/bbsk_config.txt\n")
    info(f"    VICTIM_MAC={victim_mac}   AP_MAC={ap_mac}\n\n")

    CLI(net)

    info("*** Zatrzymywanie sieci\n")
    net.stop()


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("BŁĄD: Uruchom jako root: sudo python3 topology.py")
        sys.exit(1)
    topology()
