#!/usr/bin/env python3
"""
demo: obejscie client isolation przez evil twin + csa
wrapper terminalowy wokol raport/direct_hwsim_csa.py
dwa klienty lacza sie do legalnego ap z ap_isolate=1, potem csa przerzuca je na evil twin bez izolacji
dowod: ping blokowany->dziala, pcapy zapisywane
"""

import argparse
import os
import signal
import subprocess
import sys
from pathlib import Path


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)


DEFAULT_HOSTAPD = "2.10"
DEFAULT_PMF = 2
DEFAULT_STA_PMF = 1
DEFAULT_EVIL_PMF = 0
DEFAULT_EVIL_CHANNEL = 11
DEFAULT_BEACON_COUNT = 50
DEFAULT_WAIT = 15
DEFAULT_EVIL_WAIT = 30
DEFAULT_RETRIES = 3
DEFAULT_CSA_BURSTS = 3
DEFAULT_UNTIL_SUCCESS = True
DEFAULT_CLIENTS = 2
DEFAULT_RADIOS = 6
DEFAULT_DEMO_ISOLATION = True
DEFAULT_CAPTURE_PING = True
DEFAULT_EXPERIMENTAL_WMEDIUMD_LOSS = False


def header(title):
    """naglowek sekcji demo"""
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)
    print()


def info(text):
    """info o stanie"""
    print(f"[*] {text}")


def ok(text):
    """komunikat sukcesu"""
    print(f"[OK] {text}")


def fail(text):
    """komunikat bledu"""
    print(f"[!] {text}")


def pause(enabled):
    if not enabled:
        return
    try:
        input("\n---------- Nacisnij ENTER ----------")
    except EOFError:
        print()


def sanitize(line):
    """zachowuje utf-8, usuwa crlf"""
    return line.rstrip("\r\n")


def running_as_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def candidate_roots(script_path):
    roots = []
    for parent in [script_path.parent, *script_path.parents]:
        roots.append(parent)
        roots.append(parent.parent)

    env_root = os.environ.get("PMF_BYPASS_ROOT")
    if env_root:
        roots.insert(0, Path(env_root))

    roots.extend([
        Path.cwd(),
        Path("/mnt/hgfs"),
        Path("/mnt/hgfs/client-isolation-bypass"),
        Path.home() / "client-isolation-bypass",
    ])

    seen = set()
    for root in roots:
        try:
            resolved = root.resolve()
        except OSError:
            resolved = root
        if resolved in seen:
            continue
        seen.add(resolved)
        yield resolved


def find_direct_script(override):
    if override:
        path = Path(override).expanduser()
        return path if path.exists() else None

    script_path = Path(__file__).resolve()
    for root in candidate_roots(script_path):
        candidate = root / "raport" / "direct_hwsim_csa.py"
        if candidate.exists():
            return candidate
    return None


def build_direct_cmd(args, direct_script):
    cmd = ["python3", str(direct_script)]
    if not running_as_root():
        cmd.insert(0, "sudo")

    cmd.extend([
        "--hostapd-ver", args.hostapd_ver,
        "--pmf", str(args.pmf),
        "--sta-pmf", str(args.sta_pmf),
        "--evil-pmf", str(args.evil_pmf),
        "--evil-channel", str(args.evil_channel),
        "--beacon-count", str(args.beacon_count),
        "--wait", str(args.wait),
        "--evil-wait", str(args.evil_wait),
        "--retries", str(args.retries),
        "--csa-bursts", str(args.csa_bursts),
        "--poll-interval", str(args.poll_interval),
        "--burst-gap", str(args.burst_gap),
        "--clients", str(args.clients),
        "--radios", str(args.radios),
    ])

    if args.until_success:
        cmd.append("--until-success")

    if args.experimental_wmediumd_loss:
        cmd.append("--wmediumd-loss-after-csa")
        if args.wmediumd_fallback_disconnect:
            cmd.append("--wmediumd-fallback-disconnect")
    elif args.no_wmediumd:
        cmd.append("--no-wmediumd")

    if args.demo_isolation:
        cmd.append("--demo-isolation")
    else:
        cmd.append("--no-demo-isolation")

    if args.capture_ping:
        cmd.append("--capture-ping")
    else:
        cmd.append("--no-capture-ping")

    return cmd


def fallback_cleanup():
    """awaryjne sprzatanie labu jesli skrypt zostanie przerwany"""
    cleanup_cmds = [
        ["sudo", "pkill", "-x", "hostapd"],
        ["sudo", "pkill", "-f", "^/sbin/wpa_supplicant -i wlan"],
        ["sudo", "pkill", "-x", "wpa_supplicant"],
        ["sudo", "pkill", "-x", "tcpdump"],
        ["sudo", "pkill", "-x", "wmediumd"],
        ["sudo", "ip", "netns", "delete", "sta1ns"],
        ["sudo", "ip", "netns", "delete", "sta2ns"],
        ["sudo", "modprobe", "-r", "mac80211_hwsim"],
    ]
    for cmd in cleanup_cmds:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stream_command(cmd):
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
        start_new_session=True,
    )
    stopping_child = False

    def terminate_child():
        nonlocal stopping_child
        stopping_child = True
        try:
            proc.kill()
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass

    def stop_child(_signum, _frame):
        if stopping_child:
            return
        fail("Przerwano demo, zatrzymuje test bezposredni...")
        terminate_child()
        fallback_cleanup()

    old_int = signal.signal(signal.SIGINT, stop_child)
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            cleaned = sanitize(line)
            print(f"[direct] {cleaned}")
        return proc.wait()
    finally:
        signal.signal(signal.SIGINT, old_int)


def explain_intro(args):
    header("Projekt BBSK — Demonstracja: Obejście Client Isolation (PMF Bypass) / Evil Twin + CSA")
    print("Wykonał: Kuba")
    print()
    print("Cel demonstracji:")
    print("Ukazanie słabości standardu 802.11w (Protected Management Frames) poprzez zmuszenie")
    print("klientów sieci do reasocjacji z fałszywym punktem dostępowym przy użyciu ramek Beacon.")
    print()
    print("Konfiguracja testowa:")
    print(f"- Wersja hostapd: {args.hostapd_ver}")
    print(f"- PMF: Legalny AP = {args.pmf}, Klienci = {args.sta_pmf}, Evil Twin = {args.evil_pmf}")
    print(f"- Klienci testowi: {args.clients}")


def explain_attack():
    header("Metodologia ataku")
    print("Krok 1: Uruchomienie legalnego punktu dostępowego (kanał 6, PMF włączone, izolacja aktywna).")
    print("Krok 2: Autoryzacja i asocjacja stacji testowych z legalnym AP.")
    print("Krok 3: Weryfikacja działania mechanizmu Client Isolation (ping powinien być zablokowany).")
    print("Krok 4: Start fałszywego punktu dostępowego (Evil Twin) na kanale 11 (brak izolacji).")
    print("Krok 5: Wstrzyknięcie ramek Beacon z parametrem CSA (Channel Switch Announcement).")
    print("Krok 6: Oczekiwanie na reasocjację stacji do Evil Twina.")
    print("Krok 7: Ponowna weryfikacja (ping powinien zakończyć się sukcesem — ominięto izolację).")
    print()
    print("Zrzuty PCAP zostaną automatycznie wyeksportowane do folderu raport/pcaps/csa_injection/.")


def print_result(rc):
    header("Wynik demonstracji")
    if rc == 0:
        ok("Demonstracja zakończona pomyślnie.")
        print("Materiały do dokumentacji:")
        print("  - zrzuty PCAP: raport/pcaps/csa_injection/")
        print("  - logi:        raport/logs/")
        return 0

    fail(f"Demonstracja zakończona niepowodzeniem (kod {rc}).")
    print("Szczegóły w logach:")
    print("  /tmp/direct_hwsim_csa/")
    print("  raport/logs/")
    return rc


def parse_args():
    parser = argparse.ArgumentParser(
        description="Terminal-safe demo wrapper for Beacon CSA PMF bypass."
    )
    parser.add_argument("--hostapd-ver", default=DEFAULT_HOSTAPD, choices=["2.6", "2.10"])
    parser.add_argument("--pmf", type=int, default=DEFAULT_PMF, choices=[0, 1, 2])
    parser.add_argument("--sta-pmf", type=int, default=DEFAULT_STA_PMF, choices=[0, 1, 2])
    parser.add_argument("--evil-pmf", type=int, default=DEFAULT_EVIL_PMF, choices=[0, 1, 2])
    parser.add_argument("--evil-channel", type=int, default=DEFAULT_EVIL_CHANNEL)
    parser.add_argument("--beacon-count", type=int, default=DEFAULT_BEACON_COUNT)
    parser.add_argument("--wait", type=int, default=DEFAULT_WAIT)
    parser.add_argument("--evil-wait", type=int, default=DEFAULT_EVIL_WAIT)
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    parser.add_argument("--csa-bursts", type=int, default=DEFAULT_CSA_BURSTS)
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--burst-gap", type=float, default=1.0)
    parser.add_argument("--clients", type=int, default=DEFAULT_CLIENTS)
    parser.add_argument("--radios", type=int, default=DEFAULT_RADIOS)
    parser.add_argument("--demo-isolation", dest="demo_isolation", action="store_true", default=DEFAULT_DEMO_ISOLATION)
    parser.add_argument("--no-demo-isolation", dest="demo_isolation", action="store_false")
    parser.add_argument("--capture-ping", dest="capture_ping", action="store_true", default=DEFAULT_CAPTURE_PING)
    parser.add_argument("--no-capture-ping", dest="capture_ping", action="store_false")
    parser.add_argument("--until-success", action="store_true", default=DEFAULT_UNTIL_SUCCESS)
    parser.add_argument("--no-until-success", action="store_false", dest="until_success")
    parser.add_argument("--no-wmediumd", action="store_true", default=True)
    parser.add_argument("--with-wmediumd", action="store_false", dest="no_wmediumd")
    parser.add_argument("--experimental-wmediumd-loss", action="store_true",
                        default=DEFAULT_EXPERIMENTAL_WMEDIUMD_LOSS,
                        help="Experimental: use wmediumd loss updates after CSA instead of default force-disconnect")
    parser.add_argument("--wmediumd-fallback-disconnect", action="store_true",
                        help="With --experimental-wmediumd-loss, fall back to explicit disconnect if roaming does not happen")
    parser.add_argument("--direct-script", help="Path to raport/direct_hwsim_csa.py")
    parser.add_argument("--yes", action="store_true", help="Do not pause between sections")
    return parser.parse_args()


def main():
    args = parse_args()
    interactive = not args.yes

    explain_intro(args)
    pause(interactive)
    explain_attack()
    pause(interactive)

    direct_script = find_direct_script(args.direct_script)
    if not direct_script:
        fail("Nie znaleziono raport/direct_hwsim_csa.py.")
        print("Uruchom z repo lub podaj:")
        print("  --direct-script /mnt/hgfs/raport/direct_hwsim_csa.py")
        print("Mozesz tez ustawic PMF_BYPASS_ROOT=/mnt/hgfs.")
        return 2

    header("Rozpoczęcie środowiska testowego")
    ok("Inicjalizacja skryptu direct_hwsim_csa.py w tle...")
    cmd = build_direct_cmd(args, direct_script)

    rc = stream_command(cmd)
    return print_result(rc)


if __name__ == "__main__":
    sys.exit(main())
