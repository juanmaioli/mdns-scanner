# 📡 mDNS Scanner

Herramienta de escaneo híbrido (activo y pasivo) para descubrir dispositivos que utilizan el protocolo mDNS en la red local.

## 1. 📋 Descripción

Este script identifica dispositivos IoT, impresoras y otros equipos que anuncian servicios mediante Zeroconf/Bonjour. Combina la escucha pasiva de tráfico mDNS con escaneos activos de red para proporcionar una visibilidad completa de los dispositivos conectados.

### Características Principales:
- **Detección Avanzada de Hostnames**: Utiliza scripts de `nmap` (`dns-service-discovery`) y análisis verboso de `tcpdump` para obtener nombres reales de dispositivos (ej: "Apple TV", "Chromecast").
- **Interfaz en Tiempo Real**: Tabla dinámica numerada y traducida al español.
- **Modo Híbrido**: Combina descubrimiento pasivo por tráfico y escaneo activo de subred.

## 2. 🛠️ Requisitos

Asegúrate de tener instaladas las siguientes dependencias:

### Sistema
- Linux (Debian/Ubuntu recomendado)
- `tcpdump`
- `nmap` (con soporte para scripts NSE)

### Python
- `netifaces` (Instalar con `pip install netifaces`)

## 3. 🚀 Uso

El script requiere privilegios de root para realizar capturas de red y escaneos ARP.

```bash
sudo python3 mdns-scanner.py [interfaz]
```

- Si no se especifica una interfaz, se utilizará `wlp0s20f3` por defecto.
- Presiona **'q'** en cualquier momento para salir de forma segura.