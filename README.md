# MITM Proxy for Encrypted Traffic

Este proyecto implementa un **pipeline de análisis dinámico de aplicaciones Android** que combina:

- **mitmproxy** (en VM Ubuntu) para interceptar tráfico HTTPS.
- **Addons personalizados** que detectan apps con SSL Pinning y vuelcan el tráfico a ficheros legibles.
- **Post-procesado DLP** para identificar fugas de datos sensibles (DeviceID, IMEI, Bearer tokens, coordenadas GPS...).
- **Servidor Flask** (en host Windows) que recibe los reportes de pinning, resuelve qué paquete Android los genera y puede lanzar automáticamente **Frida** para aplicar bypass SSL pinning.

---

## Arquitectura

- **VM Ubuntu (mitmproxy)**  
  Captura y análisis de tráfico HTTPS. Se elige Ubuntu por su estabilidad en la gestión de certificados, facilidad para enrutar tráfico y capacidad de aislar el entorno de captura en snapshots.

- **Host Windows (Android Studio + Frida + Flask)**  
  El emulador Android corre en Windows (aprovechando GPU/AVD, Magisk y Frida). El servidor Flask recibe eventos desde la VM Ubuntu y resuelve el mapeo **dominio → conexión activa → PID → paquete Android**, lanzando Frida si corresponde.

---

## Requisitos

### En Ubuntu (VM con mitmproxy)
- Python 3.8+
- [mitmproxy](https://mitmproxy.org/) (`pip install mitmproxy`)
- Carpeta de trabajo:
  ```bash
  mkdir trafico_bruto
  ```

### En Windows (Host con emulador Android)
- Android Studio + AVD con **root via Magisk**
- [Frida](https://frida.re/) y [frida-tools](https://frida.re/docs/home/) (`pip install frida-tools`)
- [ADB](https://developer.android.com/studio/command-line/adb) en el PATH
- Python 3.8+ para el servidor Flask

---

## Componentes del repo

- `postprocesado_dlp_v3.py`  
  Script híbrido:
  - **Standalone**: postprocesa ficheros en `trafico_bruto/` y genera:
    - `resultados_dlp.txt` (detalle por archivo interceptado)
    - `resumen_por_tipo.csv` (resumen global por tipo de fuga)
  - **Addon de mitmproxy**: al ejecutarse con `-s`:
    - Detecta errores TLS por pinning y los reporta a Flask
    - Vuelca solicitudes/respuestas a ficheros de `trafico_bruto/`

- `flask_server.py`  
  Servidor en Windows que recibe los reportes de pinning y:
  - Resuelve qué **paquete Android** está asociado al tráfico (via `ss` o `netstat` en el emulador rooteado).
  - Si está activo `RUN_FRIDA=1`, lanza **Frida** automáticamente para aplicar el bypass universal de SSL pinning.

---

## Cómo lanzarlo

### 1. Arrancar servidor Flask en Windows
```powershell
# Solo reportar (sin lanzar Frida)
set RUN_FRIDA=0
python flask_server.py

# Reportar + lanzar Frida automáticamente
set RUN_FRIDA=1
python flask_server.py
```

Por defecto escucha en `127.0.0.1:5001`.

### 2. Arrancar mitmproxy en Ubuntu
```bash
mitmproxy -p 8080 -s postprocesado_dlp_v3.py
```

Esto:
- Captura tráfico
- Vuelca flujos HTTP/HTTPS en `trafico_bruto/`
- Reporta errores de handshake SSL (pinning) al Flask

### 3. Configurar proxy en el emulador Android (Windows)
En la red del emulador, fija:
- **Proxy host** = IP de la VM Ubuntu
- **Proxy port** = 8080

Instala el certificado CA de mitmproxy en el emulador o usa **Frida** para bypass.

### 4. Post-procesado DLP
Cuando quieras analizar fugas de datos:

```bash
python postprocesado_dlp_v3.py
```

Genera:
- `resultados_dlp.txt` → detalle por flujo interceptado
- `resumen_por_tipo.csv` → resumen global de fugas (IMEI, DeviceID, Bearer tokens, etc.)

---

## Ejemplo de flujo

1. Una app en el emulador intenta conectar a `api.sporttia.com`.
2. Si la app no implementa pinning, mitmproxy intercepta y vuelca tráfico → DLP detecta un **Bearer token** o **QR SVG**.
3. Si la app implementa pinning, mitmproxy muestra error TLS → el addon lo reporta a Flask.
4. Flask resuelve qué paquete Android mantiene la conexión hacia ese dominio/IP.
5. Con `RUN_FRIDA=1`, Flask lanza automáticamente:
   ```bash
   frida --codeshare sowdust/universal-android-ssl-pinning-bypass-2 -f <PACKAGE> -U
   ```
6. El tráfico vuelve a ser interceptable y analizado.

---

## Endpoints del servidor Flask

- `POST /report_ssl_pinning`  
  Payload desde mitmproxy con `host`, `sni`, `port`, `client_peer`.

- `GET /apps_con_pinning`  
  Listado de todos los eventos recibidos.

- `GET /frida_processes`  
  Lista procesos detectables por Frida (`frida-ps -U -a`).

---

## Justificación de la arquitectura

- **Separación de planos:** Ubuntu VM para captura/mitmproxy (limpio, scriptable), Windows host para instrumentación (AVD+Magisk+Frida).
- **Compatibilidad:** Android Studio/AVD y Frida funcionan mejor en Windows con GPU/Hyper-V.
- **Robustez:** Linux maneja mejor certificados y redirección de tráfico.
- **Escalabilidad:** Se pueden añadir más VMs Ubuntu reportando al mismo Flask para orquestar bypasses de SSL.

---

## Resultados esperados

- Identificación de fugas de datos sensibles (DeviceID, IMEI, OAuth2 Bearer, QR tokens, etc).
- Clasificación de apps vulnerables a MITM por ausencia de pinning.
- Automatización de bypass SSL en apps con pinning usando Frida.

---
