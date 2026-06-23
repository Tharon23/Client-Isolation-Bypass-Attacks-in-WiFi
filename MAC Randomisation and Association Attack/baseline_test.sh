#!/bin/bash
# BBSK Projekt - Baseline Test
# Dowód że Client Isolation działa PRZED atakiem
# Uruchomienie: sudo bash baseline_test.sh
# (po uruchomieniu topology.py - z CLI Mininet-wifi)

CAPTURES_DIR="$HOME/bbsk-projekt/captures"
mkdir -p "$CAPTURES_DIR"

echo "================================================"
echo "  BBSK - BASELINE TEST (Client Isolation)"
echo "================================================"
echo ""
echo "Ten skrypt dokumentuje że izolacja klientów"
echo "poprawnie blokuje komunikację sta1↔sta2."
echo ""

# Sprawdź czy jesteśmy w środowisku Mininet
if ! ip netns list 2>/dev/null | grep -q "sta"; then
    echo "[!] Brak przestrzeni nazw Mininet. Uruchom najpierw:"
    echo "    sudo python3 ~/bbsk-projekt/topology.py"
    echo ""
    echo "Następnie z CLI Mininet-wifi wpisz:"
    echo "    mininet-wifi> noecho bash ~/bbsk-projekt/baseline_test.sh"
    exit 1
fi

echo "--- TEST 1: sta1 ping sta2 (powinno FAILOWAĆ) ---"
echo ""
ip netns exec sta1 ping -c 5 -W 1 10.0.0.2
if [ $? -eq 0 ]; then
    echo "[UWAGA] Ping przeszedł! Izolacja może być wyłączona."
    RESULT1="FAIL (izolacja nie działa)"
else
    echo "[OK] Ping zablokowany - izolacja działa"
    RESULT1="PASS (izolacja działa)"
fi

echo ""
echo "--- TEST 2: sta1 ping h1 (powinno DZIAŁAĆ) ---"
echo ""
ip netns exec sta1 ping -c 5 -W 1 10.0.0.100
if [ $? -eq 0 ]; then
    echo "[OK] Ping do hosta przeszedł"
    RESULT2="PASS (routing działa)"
else
    echo "[!] Ping do hosta nie przeszedł - sprawdź konfigurację"
    RESULT2="FAIL (brak łączności z hostem)"
fi

echo ""
echo "--- TEST 3: Zapis PCAP na 10 sekund ---"
echo ""
PCAP_FILE="$CAPTURES_DIR/baseline_$(date +%Y%m%d_%H%M%S).pcap"
echo "Zapisuję ruch do: $PCAP_FILE"
echo "(Uruchamianie pingu w tle i capture...)"

# Generuj ruch w tle
ip netns exec sta1 ping -c 20 -i 0.5 10.0.0.2 > /dev/null 2>&1 &
PING_PID=$!

# Zbieraj PCAP
timeout 10 tcpdump -i ap1-wlan0 -w "$PCAP_FILE" -n 2>/dev/null &
TCPDUMP_PID=$!
sleep 11
kill $PING_PID 2>/dev/null
kill $TCPDUMP_PID 2>/dev/null
wait 2>/dev/null

if [ -f "$PCAP_FILE" ]; then
    SIZE=$(du -h "$PCAP_FILE" | cut -f1)
    echo "[OK] PCAP zapisany: $PCAP_FILE ($SIZE)"
    echo ""
    echo "Filtr Wireshark: icmp && ip.src == 10.0.0.1 && ip.dst == 10.0.0.2"
else
    echo "[!] PCAP nie został zapisany"
fi

echo ""
echo "================================================"
echo "  PODSUMOWANIE BASELINE"
echo "================================================"
echo "  sta1 → sta2 (izolacja): $RESULT1"
echo "  sta1 → h1   (routing):  $RESULT2"
echo "  PCAP: $PCAP_FILE"
echo ""
echo "Następny krok: uruchom atak:"
echo "  mininet-wifi> py exec(open('/root/bbsk-projekt/attack.py').read())"
echo "================================================"
