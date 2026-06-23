#!/bin/bash


set -e

echo ""
echo "============================================================"
echo "  BBSK - MAC Spoofing + Association Hijacking"
echo "  skrypt startowy"
echo "============================================================"
echo ""


if [ "$EUID" -ne 0 ]; then
    echo "  blad: uruchom jako root: sudo bash uruchom.sh"
    exit 1
fi

echo "  [1/4] uruchamianie Open vSwitch..."
service openvswitch-switch start 2>/dev/null || true
sleep 1

if ! ovs-vsctl show &>/dev/null; then
    echo "  blad: OVS nie odpowiada, probuje jeszcze raz..."
    service openvswitch-switch restart
    sleep 2
fi
echo "  ok"
echo ""


echo "  [2/4] czyszczenie poprzedniej sesji mininet..."
mn -c 2>/dev/null || true
echo "  ok"
echo ""

echo "  [3/4] ladowanie wirtualnych kart wifi..."
modprobe mac80211_hwsim radios=4
echo "  ok"
echo ""

echo "  [4/4] uruchamianie topologii..."
echo ""
echo "  po uruchomieniu w CLI mininet-wifi nalezy wpisac:"
echo ""
echo "      sta2 python3 /home/kali/bbsk-projekt/demo.py"
echo ""
echo "============================================================"
echo ""

sleep 2

python3 /home/kali/bbsk-projekt/topology.py
