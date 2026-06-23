#!/bin/bash
# ==============================================================================
# PMF Lab VM Helper — installed on Kali VM at /usr/local/bin/lab-run
# 
# Solves SSH tool-calling issues by accepting commands as files,
# not inline strings. All execution goes through VMware share.
#
# Usage:
#   lab-run python  script.py      # sudo python3 /mnt/hgfs/raport/script.py
#   lab-run bash   script.sh       # sudo bash /mnt/hgfs/raport/script.sh
#   lab-run test   isolation       # run baseline test + log to raport/
#   lab-run clean                  # sudo mn -c + modprobe reset
#   lab-run sync                   # rsync host→VM
#   lab-run status                 # check hwsim, OVS, Python versions
# ==============================================================================

set -e

SHARE="/mnt/hgfs"
RAPORT="$SHARE/raport"
REPO="$HOME/pmf-bypass-lab-infra"
SHARE_REPO="$SHARE/pmf-bypass-lab-infra"
HOSTAPD_210_BACKUP="/usr/sbin/hostapd-2.10.bak"

ensure_hostapd_210() {
    local current
    current="$(hostapd -v 2>&1 | head -1 || true)"
    if echo "$current" | grep -q "v2\.6" && [ -f "$HOSTAPD_210_BACKUP" ]; then
        sudo cp "$HOSTAPD_210_BACKUP" /usr/sbin/hostapd
        sudo chmod +x /usr/sbin/hostapd
    fi
}

cmd_clean() {
    echo "=== Cleaning Mininet-WiFi state ==="
    sudo mn -c 2>/dev/null || true
    sudo modprobe -r mac80211_hwsim 2>/dev/null || true
    sleep 1
    sudo modprobe mac80211_hwsim radios=4
    sleep 1
    iw dev | grep -c Interface
    echo "=== Clean done ==="
}

cmd_sync() {
    echo "=== Syncing host -> VM ==="
    rsync -av --delete "$SHARE_REPO/" "$REPO/"
    echo "=== Sync done ==="
}

cmd_status() {
    ensure_hostapd_210
    echo "=== Lab Status ==="
    echo -n "hwsim radios: "; iw dev 2>/dev/null | awk '/Interface / {n++} END {print n+0}'
    echo -n "OVS: "; sudo systemctl is-active openvswitch-switch 2>/dev/null || echo "inactive"
    echo -n "Python: "; python3 --version
    echo -n "Scapy: "; python3 -c "import scapy;print(scapy.__version__)" 2>/dev/null || echo "MISSING"
    echo -n "mn_wifi: "; python3 -c "import mn_wifi;print('OK')" 2>/dev/null || echo "MISSING"
    echo -n "hostapd: "; hostapd -v 2>&1 | head -1 || echo "MISSING"
    echo -n "Repo: "; test -d "$REPO/topology" && echo "OK" || echo "MISSING"
}

cmd_python() {
    local script="$RAPORT/$1"
    shift
    sudo python3 "$script" "$@"
}

cmd_bash() {
    local script="$RAPORT/$1"
    shift
    sudo bash "$script" "$@"
}

cmd_test() {
    local test_name="$1"
    cmd_clean
    case "$test_name" in
        isolation)
            sudo python3 "$REPO/baseline/test_isolation.py" 2>&1 | tee "$RAPORT/logs/isolation_$(date +%Y%m%d_%H%M%S).log"
            ;;
        pmf)
            sudo python3 "$REPO/baseline/test_pmf.py" 2>&1 | tee "$RAPORT/logs/pmf_$(date +%Y%m%d_%H%M%S).log"
            ;;
        csa)
            sudo python3 "$REPO/baseline/test_csa.py" 2>&1 | tee "$RAPORT/logs/csa_$(date +%Y%m%d_%H%M%S).log"
            ;;
        all)
            cmd_test isolation
            cmd_test pmf
            cmd_test csa
            ;;
        *)
            echo "Unknown test: $test_name"
            echo "Available: isolation, pmf, csa, all"
            ;;
    esac
}

cmd_attack() {
    local attack="$1"
    shift
    cmd_clean
    case "$attack" in
        csa)
            sudo python3 "$REPO/attacks/csa_injection.py" "$@" 2>&1 | tee "$RAPORT/logs/attack_csa_$(date +%Y%m%d_%H%M%S).log"
            ;;
        beacon)
            sudo python3 "$REPO/attacks/beacon_csa.py" "$@" 2>&1 | tee "$RAPORT/logs/attack_beacon_$(date +%Y%m%d_%H%M%S).log"
            ;;
        sa)
            sudo python3 "$REPO/attacks/sa_query_flood.py" "$@" 2>&1 | tee "$RAPORT/logs/attack_sa_$(date +%Y%m%d_%H%M%S).log"
            ;;
        direct-csa)
            sudo python3 "$RAPORT/direct_hwsim_csa.py" "$@" 2>&1 | tee "$RAPORT/logs/attack_direct_csa_$(date +%Y%m%d_%H%M%S).log"
            ;;
        *)
            echo "Unknown attack: $attack"
            echo "Available: csa, beacon, sa, direct-csa"
            ;;
    esac
}

# ---- Main ----
case "${1:-}" in
    clean)    cmd_clean ;;
    sync)     cmd_sync ;;
    status)   cmd_status ;;
    python)   shift; cmd_python "$@" ;;
    bash)     shift; cmd_bash "$@" ;;
    test)     shift; cmd_test "$@" ;;
    attack)   shift; cmd_attack "$@" ;;
    *)
        echo "Usage: lab-run {clean|sync|status|python|bash|test|attack} [args...]"
        echo ""
        echo "  clean              Reset Mininet-WiFi state"
        echo "  sync               Rsync host repo → VM"
        echo "  status             Show lab environment status"
        echo "  python script.py   Run Python script from raport/"
        echo "  bash script.sh     Run bash script from raport/"
        echo "  test isolation|pmf|csa|all   Run baseline test"
        echo "  attack csa|sa [args]         Run attack module"
        ;;
esac
