# 📡 mDNS Scanner

Herramienta de escaneo híbrido (activo y pasivo) para descubrir dispositivos que utilizan el protocolo mDNS en la red local.

## 1. 📋 Descripción

Este script permite identificar dispositivos IoT, impresoras y otros equipos que anuncian servicios mediante Zeroconf/Bonjour. Combina la escucha pasiva de tráfico mDNS con escaneos activos de red para proporcionar una visibilidad completa de los dispositivos conectados.

## 2. 🛠️ Requisitos

Para que el script funcione correctamente, asegúrate de tener instaladas las siguientes dependencias:

### Sistema
- Linux (Debian/Ubuntu recomendado)
- `tcpdump`
- `nmap`

### Python
- `netifaces` (Instalar con `pip install netifaces`)

## 3. 🚀 Uso

El script requiere privilegios de root para realizar capturas de red y escaneos ARP.

```bash
sudo python3 mdns-scanner.py [interfaz]
```

Si no se especifica una interfaz, se utilizará `wlp0s20f3` por defecto.
