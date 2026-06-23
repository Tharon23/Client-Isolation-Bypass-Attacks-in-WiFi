#!/usr/bin/env python3
"""
============================================================
Atak AirSnitch - Topologia Sieciowa
Emulacja sieci hotelowej z izolacją klientów Wi-Fi
============================================================
"""

from mininet.log import setLogLevel, info
from mn_wifi.net import Mininet_wifi
from mn_wifi.cli import CLI


def topology():
    """Topologia sieciowa hotelu do demonstracji ataku AirSnitch"""

    net = Mininet_wifi()

    info("*** Tworzenie węzłów\n")

    # ── Access Point z włączoną izolacją klientów ──
    ap1 = net.addAccessPoint(
        'ap1',
        ssid='SiecHotelowa',
        mode='g',
        channel='1',
        client_isolation=True
    )

    # ── Ofiary (goście hotelowi) ──
    sta1 = net.addStation('sta1', ip='192.168.10.2/24',
                          mac='00:00:00:00:00:01')
    sta2 = net.addStation('sta2', ip='192.168.10.3/24',
                          mac='00:00:00:00:00:02')

    # ── Atakujący (złośliwy gość hotelowy) ──
    atk1 = net.addStation('atk1', ip='192.168.10.4/24',
                          mac='00:00:00:00:00:66')

    # ── Brama sieciowa / Router (połączona kablem do AP) ──
    gw = net.addHost('gw', ip='192.168.10.1/24',
                     mac='00:00:00:00:00:FF')

    c1 = net.addController('c1')

    info("*** Konfiguracja węzłów Wi-Fi\n")
    net.configureWifiNodes()

    info("*** Dodawanie linków\n")
    net.addLink(sta1, ap1)
    net.addLink(sta2, ap1)
    net.addLink(atk1, ap1)
    net.addLink(ap1, gw)  # Połączenie kablem między AP a Bramą

    info("*** Budowanie sieci\n")
    net.build()
    c1.start()
    ap1.start([c1])

    # ── Konfiguracja bramy sieciowej ──
    info("*** Konfiguracja bramy sieciowej\n")

    # Włączenie przekazywania IP na bramie
    # Mechanizm ten umożliwia atak Gateway Bouncing
    gw.cmd('sysctl -w net.ipv4.ip_forward=1')

    # Ustawienie bramy domyślnej na wszystkich stacjach
    sta1.cmd('ip route add default via 192.168.10.1')
    sta2.cmd('ip route add default via 192.168.10.1')
    atk1.cmd('ip route add default via 192.168.10.1')

    # ── Serwer HTTP na bramie (symulacja usługi hotelowej) ──
    info("*** Uruchomienie serwera HTTP na bramie\n")
    gw.cmd('mkdir -p /tmp/www')
    gw.cmd(
        'echo "<html><body>'
        '<h1>Portal Hotelowy - Strefa Goscia</h1>'
        '<p>Numer pokoju: 302</p>'
        '<p>Haslo WiFi: Hotel2024!</p>'
        '<p>Nr karty kredytowej: 4532-XXXX-XXXX-7890</p>'
        '</body></html>" > /tmp/www/index.html'
    )
    gw.cmd('echo "TAJNE_DANE:login=admin,haslo=SuperSecret123" '
           '> /tmp/www/secret.txt')
    gw.cmd('cd /tmp/www && python3 -m http.server 80 &')

    # ── Prosty serwer HTTP na sta1 (do wykrycia przez skan portów) ──
    info("*** Uruchomienie prostego serwera na sta1 (port 80)\n")
    sta1.cmd('mkdir -p /tmp/sta1www')
    sta1.cmd('echo "<html><body><h1>Strona ofiary</h1>'
             '<p>Prywatne dane sta1</p></body></html>" '
             '> /tmp/sta1www/index.html')
    sta1.cmd('cd /tmp/sta1www && python3 -m http.server 80 &')

    # ── Automatyczny tcpdump na wszystkich stacjach ──
    info("*** Uruchomienie tcpdump na sta1, atk1, gw (auto-PCAP)\n")
    sta1.cmd('tcpdump -i sta1-wlan0 -w /tmp/sta1_capture.pcap '
             '-U 2>/dev/null &')
    atk1.cmd('tcpdump -i atk1-wlan0 -w /tmp/atk1_capture.pcap '
             '-U 2>/dev/null &')
    gw.cmd('tcpdump -i gw-eth0 -w /tmp/gw_capture.pcap '
           '-U 2>/dev/null &')

    # ── Banner informacyjny ──
    info("\n" + "=" * 60 + "\n")
    info("  AirSnitch - Środowisko gotowe!\n")
    info("=" * 60 + "\n")
    info("Węzły sieci:\n")
    info("  sta1 (Ofiara 1) : 192.168.10.2  [00:00:00:00:00:01]\n")
    info("  sta2 (Ofiara 2) : 192.168.10.3  [00:00:00:00:00:02]\n")
    info("  atk1 (Atakujący): 192.168.10.4  [00:00:00:00:00:66]\n")
    info("  gw   (Brama)    : 192.168.10.1  [00:00:00:00:00:FF]\n")
    info("\n")
    info("Serwer HTTP bramy: http://192.168.10.1/\n")
    info("Serwer HTTP sta1 : http://192.168.10.2/ (port 80)\n")
    info("Client Isolation : WŁĄCZONA\n")
    info("\n")
    info("╔═══════════════════════════════════════════════════════╗\n")
    info("║  PCAP nagrywanie AKTYWNE (automatyczne)               ║\n")
    info("║  Pliki zapisywane w /tmp/:                            ║\n")
    info("║    sta1_capture.pcap  - ruch na sta1                  ║\n")
    info("║    atk1_capture.pcap  - ruch na atk1                  ║\n")
    info("║    gw_capture.pcap    - ruch na bramie                ║\n")
    info("╚═══════════════════════════════════════════════════════╝\n")
    info("\n")
    info("Ataki:\n")
    info("  atk1 python3 airsnitch_bounce.py    # Gateway Bouncing\n")
    info("  atk1 python3 airsnitch_intercept.py # Przechwytywanie\n")
    info("  atk1 python3 airsnitch_mitm.py      # Pełny MitM\n")
    info("=" * 60 + "\n\n")

    CLI(net)

    # Zatrzymanie procesów w tle
    info("*** Zatrzymywanie tcpdump i serwerów...\n")
    sta1.cmd('kill %tcpdump 2>/dev/null')
    atk1.cmd('kill %tcpdump 2>/dev/null')
    gw.cmd('kill %tcpdump 2>/dev/null')
    sta1.cmd('kill %python3 2>/dev/null')
    gw.cmd('kill %python3 2>/dev/null')
    info("*** Pliki PCAP zapisane w /tmp/\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
