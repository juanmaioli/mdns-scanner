#!/usr/bin/env python3
import subprocess
import threading
import re
import signal
import sys
import os
import time
import socket
import netifaces
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import shutil
import select
import tty
import termios

stop_event = threading.Event()



INTERFACE = sys.argv[1] if len(sys.argv) > 1 else "wlp0s20f3"

try:
    addrs = netifaces.ifaddresses(INTERFACE)
    ipv4 = addrs.get(netifaces.AF_INET)
    if not ipv4:
        print(f"[!] La interfaz {INTERFACE} no tiene dirección IPv4")
        sys.exit(1)
    ip = ipv4[0]['addr']
    BASE_IP = '.'.join(ip.split('.')[:3]) + '.'
except Exception as e:
    print(f"[!] No se pudo obtener la IP de la interfaz '{INTERFACE}': {e}")
    sys.exit(1)

print(f"[*] Usando interfaz {INTERFACE} (IP base: {BASE_IP})")


def require_root():
    if os.geteuid() != 0:
        print("[ERROR] Este script debe ejecutarse como root.")
        print("        Se requieren privilegios de root para ejecutar tcpdump y operaciones de red.")
        print("\n        Inténtalo de nuevo usando:\n            sudo python3 mdns-scanner.py <interfaz>\n")
        sys.exit(1)




HAS_NMAP = shutil.which("nmap") is not None
HAS_TCPDUMP = shutil.which("tcpdump") is not None



if HAS_NMAP:
    pass
else:
    print("[ADVERTENCIA] nmap NO encontrado. Escáner activo desactivado.")

if HAS_TCPDUMP:
    pass
else:
    print("[ADVERTENCIA] tcpdump NO encontrado. Escáner pasivo desactivado.")



START = 1
END = 255
PORT = "5353"
MAX_THREADS = 20
ACTIVE_INTERVAL = 3

RESET = "\033[0m"
GREEN = "\033[92m"
YELLOW = "\033[93m"


OUI = {
    "28:CF:E9": "Apple, Inc.",
    "DC:A6:32": "Apple, Inc.",
    "40:CB:C0": "Apple, Inc.",
    "F4:F5:D8": "Google, Inc.",
    "3C:5A:B4": "Google Nest",
    "F0:9F:C2": "Amazon",
    "50:02:91": "Espressif",
    "7C:DF:A1": "Espressif",
    "84:CC:A8": "Samsung",
    "00:1A:79": "Sony",
}

hosts = []
lock = threading.Lock()


def oui_lookup(mac):
    if not mac or ":" not in mac:
        return "Unknown"
    prefix = ":".join(mac.upper().split(":")[0:3])
    return OUI.get(prefix, "Unknown")


def get_mac(ip):
    try:
        out = subprocess.check_output(["ip", "neigh"], text=True)
        for line in out.splitlines():
            if ip in line and "lladdr" in line:
                m = re.search(r"lladdr ([0-9a-f:]+)", line)
                if m:
                    return m.group(1)
    except:
        pass
    return None


def update_table():
    os.system("clear")

    if not hosts:
        print("No se han descubierto hosts todavía...")
        print("\nPresiona 'q' para salir\n")
        return

    ordered = sorted(hosts, key=lambda h: list(map(int, h["ip"].split("."))))

    print("+----------------+-------------------+----------------------+---------------------+-----------+")
    print("| IP             | MAC               | Fabricante           | Última vez visto    | Método    |")
    print("+----------------+-------------------+----------------------+---------------------+-----------+")

    for h in ordered:
        method_color = GREEN if h["method"] == "Activo" else YELLOW
        vendor = h["vendor"][:20]
        print(f"| {h['ip']:<14} | {h['mac']:<17} | {vendor:<20} | {h['last_seen']:<19} | "
              f"{method_color}{h['method']:<9}{RESET} |")

    print("+----------------+-------------------+----------------------+---------------------+-----------+")
    print("Presiona 'q' para salir\n")



def add_host(ip, mac, method, vendor_override=None):
    with lock:
        for h in hosts:
            if h["ip"] == ip:

                h["last_seen"] = datetime.now().strftime("%H:%M:%S")

                if method == "Activo":
                    h["method"] = "Activo"

                if mac:
                    h["mac"] = mac

                curr = h["vendor"]

                if vendor_override and vendor_override not in ["Desconocido", "(Desconocido)"]:
                    if curr in ["Desconocido", "(Desconocido)"]:
                        h["vendor"] = vendor_override
                    elif "." in curr:
                        h["vendor"] = vendor_override

                update_table()
                return

        hosts.append({
            "ip": ip,
            "mac": mac if mac else "(desconocido)",
            "vendor": vendor_override if vendor_override else "(Desconocido)",
            "method": method,
            "last_seen": datetime.now().strftime("%H:%M:%S")
        })
        update_table()


def passive_sniffer(interface):
    cmd = ["tcpdump", "-l", "-n", "-i", interface, "udp port 5353"] # TCPDUMP requiere root para funcionar correctamente
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True)

    while not stop_event.is_set():
        # Usamos select para no bloquearnos si no hay salida
        r, _, _ = select.select([proc.stdout], [], [], 0.5)
        if r:
            line = proc.stdout.readline()
            if not line:
                break
            m = re.search(r"IP (\d+\.\d+\.\d+\.\d+)", line)
            if not m:
                continue

            ip = m.group(1)
            mac = get_mac(ip)

            vendor_override = None
            mname = re.search(r'PTR\s+"?([^"\s{},]+)', line)
            if mname:
                name = mname.group(1)
                if not name.startswith(("(", "{")):
                    vendor_override = name.capitalize()

            add_host(ip, mac, "Pasivo", vendor_override)
    
    proc.terminate()


def scan_ip(ip):
    if not HAS_NMAP or stop_event.is_set():
        return

    try:
        result = subprocess.run(
            ["nmap", "-n", "-Pn", "-sU", "-T4", "-p", PORT, ip],
            capture_output=True,
            text=True,
            timeout=10
        )
    except:
        return

    if "zeroconf" not in result.stdout.lower():
        return

    mac = None
    vendor_from_nmap = None

    for line in result.stdout.splitlines():
        if "MAC Address" in line:
            m_mac = re.search(r"MAC Address: ([0-9a-f:]+)", line, re.I)
            if m_mac:
                mac = m_mac.group(1)

            m_vendor = re.search(r"\((.*?)\)", line)
            if m_vendor:
                vendor_from_nmap = m_vendor.group(1).strip()

    add_host(ip, mac, "Activo", vendor_override=vendor_from_nmap)


def active_scanner_loop():
    if not HAS_NMAP:
        return

    ips = [f"{BASE_IP}{i}" for i in range(START, END + 1)]
    while not stop_event.is_set():
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            for ip in ips:
                if stop_event.is_set():
                    break
                executor.submit(scan_ip, ip)
        
        # Espera interrumpible
        for _ in range(ACTIVE_INTERVAL * 10):
            if stop_event.is_set():
                break
            time.sleep(0.1)


def listen_for_quit():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while not stop_event.is_set():
            if select.select([sys.stdin], [], [], 0.1)[0]:
                if sys.stdin.read(1).lower() == 'q':
                    stop_event.set()
                    break
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


if __name__ == "__main__":
    require_root()
    update_table()

    threading.Thread(target=passive_sniffer, args=(INTERFACE,), daemon=True).start()
    threading.Thread(target=listen_for_quit, daemon=True).start()


    if HAS_NMAP:
        try:
            active_scanner_loop()
        except KeyboardInterrupt:
            pass
    else:
        try:
            while not stop_event.is_set():
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass
    
    print("\n[!] Saliendo...")
    sys.exit(0)
