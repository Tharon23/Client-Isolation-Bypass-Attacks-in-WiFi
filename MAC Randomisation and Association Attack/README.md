# MAC Randomization & Association Attack

CVE-2022-47522 | środowisko: Kali Linux, Mininet-wifi, Scapy

---

## O co chodzi

Client Isolation to funkcja w routerach która ma blokować komunikację między klientami tej samej sieci wifi. Idea jest prosta — nawet jeśli atakujący jest w tej samej sieci co ofiara, nie powinien móc dosięgnąć jej ruchu.

Okazuje się że to nie działa tak jak powinno.

Access Point rozróżnia klientów po adresie MAC. Problem w tym że standard 802.11 nie sprawdza czy klient który łączy się z danym MAC-em to ta sama osoba co poprzednio. Autentykacja (hasło WPA2) i rutowanie ruchu (adres MAC) to dwa niezależne mechanizmy — i właśnie ta niezależność jest luką.

Atak polega na tym żeby:
1. odczytać MAC ofiary z ruchu w sieci (nagłówki ramek 802.11 nie są szyfrowane)
2. rozłączyć ofiarę przez sfałszowane ramki Deauth (możliwe gdy PMF jest wyłączone)
3. zmienić własny MAC na MAC ofiary
4. połączyć się z AP — AP aktualizuje tablicę asocjacji
5. od tej chwili ruch adresowany do ofiary trafia do atakującego

---

## Warunki

- PMF (802.11w) wyłączone — ramki Deauth są bez podpisu, każdy może podszyć się pod kogokolwiek
- atakujący w zasięgu tej samej sieci wifi
- hasło WPA2 nie jest wymagane do podstawowego wariantu ataku

---

## Środowisko

- Kali Linux (VM, VirtualBox)
- Mininet-wifi z mac80211_hwsim (wirtualne karty wifi)
- hostapd, wpa_supplicant, Open vSwitch
- Scapy (budowanie i wysyłanie ramek 802.11)
- Python 3

## Topologia

```
sta1 (ofiara, 10.0.0.1)    sta2 (atakujący, 10.0.0.2)
            \                       /
             -------- ap1 ----------
                        |
                    h1 (serwer, 10.0.0.100)
```

AP ma włączone `client_isolation=True` — sta1 i sta2 nie mogą się pingować.
h1 jest podłączony kablem i symuluje serwer wysyłający dane do klientów.

---

## Uruchomienie

```bash
# 1. start środowiska
sudo bash /home/kali/bbsk-projekt/uruchom.sh

# 2. w CLI mininet-wifi uruchom demo
mininet-wifi> sta2 python3 /home/kali/bbsk-projekt/demo.py
```

Skrypt `uruchom.sh` automatycznie:
- startuje Open vSwitch
- czyści poprzednią sesję mininet
- ładuje moduł mac80211_hwsim (4 wirtualne karty)
- uruchamia topologię

Demo zatrzymuje się na każdym kroku i czeka na Enter — można na bieżąco tłumaczyć co się dzieje.

---

## Pliki

| plik | opis |
|------|------|
| `topology.py` | topologia sieci — AP, sta1, sta2, h1 |
| `demo.py` | skrypt ataku krok po kroku z komentarzami |
| `attack.py` | uproszczona wersja ataku bez przerw |
| `baseline_test.sh` | test izolacji przed atakiem |
| `uruchom.sh` | skrypt startowy — odpala wszystko od zera |
| `captures/` | pliki pcap generowane podczas ataku |
| `logs/` | logi z przebiegiem ataku |

---

## Wyniki

Baseline: `sta2 → sta1` — 100% packet loss, izolacja działa.

Po ataku: tcpdump/scapy na sta2 przechwytuje pakiety `h1 → 10.0.0.1` (ICMP echo request). Łącznie przechwycono 8 pakietów adresowanych do IP ofiary, mimo że client isolation była włączona przez cały czas.

---

## Dlaczego to działa

Client isolation blokuje bezpośrednie przesyłanie ramek L2 między klientami. Nie weryfikuje natomiast tożsamości przy asocjacji. Po reassocjacji z MAC-em ofiary AP zmienia wpis w tablicy asocjacji — adres ofiary zaczyna wskazywać na port atakującego. Ruch trafia do atakującego bo AP po prostu nie ma mechanizmu który by temu zapobiegł.

---

## Literatura

- CVE-2022-47522: https://www.cvedetails.com/cve/CVE-2022-47522/
- Vanhoef, M. et al. — *Framing Frames: Bypassing Wi-Fi Encryption by Manipulating Transmit Queues*, USENIX Security 2023
- MacStealer PoC: https://github.com/vanhoefm/macstealer
