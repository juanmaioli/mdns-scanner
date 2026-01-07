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


def get_hostname(ip):
    try:
        # Intento 1: Resolución estándar (funciona si nss-mdns está configurado)
        return socket.gethostbyaddr(ip)[0]
    except:
        try:
            # Intento 2: Usar avahi-resolve si está disponible
            out = subprocess.check_output(["avahi-resolve", "-a", ip], text=True, stderr=subprocess.DEVNULL)
            return out.split()[-1]
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

    print("+----------------+-------------------+----------------------+----------------------+-----------+")
    print("| IP             | MAC               | Fabricante           | Nombre de Host       | Método    |")
    print("+----------------+-------------------+----------------------+----------------------+-----------+")

    for h in ordered:
        method_color = GREEN if h["method"] == "Activo" else YELLOW
        vendor = h["vendor"][:20]
        hostname = h["hostname"][:20]
        print(f"| {h['ip']:<14} | {h['mac']:<17} | {vendor:<20} | {hostname:<20} | "
              f"{method_color}{h['method']:<9}{RESET} |")

    print("+----------------+-------------------+----------------------+----------------------+-----------+")
    print("Presiona 'q' para salir\n")



def add_host(ip, mac, method, vendor_override=None, hostname=None):
    with lock:
        # Si no tenemos hostname, intentamos resolverlo
        if not hostname or hostname in ["(desconocido)", "Desconocido"]:
            hostname = get_hostname(ip)

        for h in hosts:
            if h["ip"] == ip:
                if method == "Activo":
                    h["method"] = "Activo"
                if mac:
                    h["mac"] = mac
                
                if vendor_override and vendor_override not in ["Desconocido", "(Desconocido)"]:
                    h["vendor"] = vendor_override
                
                if hostname and hostname not in ["(desconocido)", "Desconocido"]:
                    h["hostname"] = hostname

                update_table()
                return

        hosts.append({
            "ip": ip,
            "mac": mac if mac else "(desconocido)",
            "vendor": vendor_override if vendor_override else "(Desconocido)",
            "hostname": hostname if hostname else "(desconocido)",
            "method": method
        })
        update_table()


def passive_sniffer(interface):
    # Añadimos -v para ver los registros mDNS (PTR, SRV, A, etc.)
    cmd = ["tcpdump", "-l", "-n", "-v", "-i", interface, "udp port 5353"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True)

    while not stop_event.is_set():
        r, _, _ = select.select([proc.stdout], [], [], 0.5)
        if r:
            line = proc.stdout.readline()
            if not line:
                break
            
            # Buscar IP de origen
            m_ip = re.search(r"IP (\d+\.\d+\.\d+\.\d+)", line)
            if not m_ip:
                continue
            ip = m_ip.group(1)
            
            # Buscar cualquier nombre que termine en .local
            # Ej: MacBook-Pro.local. o _googlecast._tcp.local.
            hostname = None
            m_local = re.search(r"([\w\d\-\.]+?\.local)\.?", line, re.I)
            if m_local:
                name = m_local.group(1)
                # Ignorar nombres de servicio comunes para quedarnos con el del dispositivo
                if not name.startswith("_") and ".local" in name:
                    hostname = name

            mac = get_mac(ip)
            add_host(ip, mac, "Pasivo", hostname=hostname)
    
    proc.terminate()


def scan_ip(ip):
    if not HAS_NMAP or stop_event.is_set():
        return

    try:
        # Usamos el script especializado dns-service-discovery de nmap
        result = subprocess.run(
            ["nmap", "-Pn", "-sV", "-p", PORT, "--script", "dns-service-discovery", ip],
            capture_output=True,
            text=True,
            timeout=20
        )
    except:
        return

    # Si no hay indicios de mDNS, ignoramos
    if "5353" not in result.stdout:
        return

    mac = None
    vendor_from_nmap = None
    hostname = None

    # 1. Intentar sacar el nombre del script de nmap (suele ser el más real)
    # nmap suele ponerlo en líneas como: "|   Device Name: Mi-Dispositivo"
    m_dev_name = re.search(r"Device Name: (.*)", result.stdout, re.I)
    if m_dev_name:
        hostname = m_dev_name.group(1).strip()
    
    # 2. Respaldo: Nombre del reporte de nmap
    if not hostname:
        m_host = re.search(r"Nmap scan report for (.*?) \(", result.stdout)
        if m_host:
            hostname = m_host.group(1).strip()

    # 3. Respaldo: Buscar .local en el output completo de nmap
    if not hostname:
        m_local = re.search(r"([\w\d\-\.]+?\.local)", result.stdout, re.I)
        if m_local:
            hostname = m_local.group(1).strip()

    for line in result.stdout.splitlines():
        if "MAC Address" in line:
            m_mac = re.search(r"MAC Address: ([0-9a-f:]+)", line, re.I)
            if m_mac:
                mac = m_mac.group(1)

            m_vendor = re.search(r"\((.*?)\)", line)
            if m_vendor:
                vendor_from_nmap = m_vendor.group(1).strip()

    add_host(ip, mac, "Activo", vendor_override=vendor_from_nmap, hostname=hostname)


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
