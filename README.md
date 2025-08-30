# MITM Proxy for Encrypted Traffic – Experimental Pipeline

This repository contains the code and documentation of the Master's Thesis project **"Proxy MITM para Tráfico Cifrado"**.

## Structure
- `addons_mitm/` : mitmproxy addons for app classification and reporting SSL pinning errors
- `dlp/` : scripts for post-processing intercepted traffic (DLP)
- `orchestrator_flask/` : Flask server to automate SSL bypass using Frida
- `frida/` : universal SSL pinning bypass script for Android apps

Adapted to my experimental environment. It includes TODOs for future improvements.


## Architecture

- **Ubuntu VM (mitmproxy)**  
  Used for HTTPS traffic capture and analysis. Ubuntu was chosen for its stability in certificate management, ease of routing traffic, and the ability to isolate the capture environment using snapshots.

- **Windows Host (Android Studio + Frida + Flask)**  
  The Android emulator runs on Windows (leveraging GPU/AVD, Magisk and Frida). The Flask server receives events from the Ubuntu VM and resolves the mapping **domain → active connection → PID → Android package**, triggering Frida if needed.

---

## Requirements

### On Ubuntu (VM with mitmproxy)
- Python 3.8+
- [mitmproxy](https://mitmproxy.org/) (`pip install mitmproxy`)
- Working folder:
  ```bash
  mkdir raw_traffic
  ```

### On Windows (Host with Android emulator)
- Android Studio + AVD with **Magisk root**
- [Frida](https://frida.re/) and [frida-tools](https://frida.re/docs/home/) (`pip install frida-tools`)
- [ADB](https://developer.android.com/studio/command-line/adb) in PATH
- Python 3.8+ for the Flask server

---

## Repository Components

- `postprocesado_dlp_v3.py`  
  Hybrid script:
  - **Standalone**: post-processes files in `raw_traffic/` and generates:
    - `dlp_results.txt` (detailed per intercepted file)
    - `summary_by_type.csv` (global summary by data type)
  - **mitmproxy addon**: when executed with `-s`:
    - Detects TLS errors caused by pinning and reports them to Flask
    - Dumps HTTP/HTTPS requests and responses into `raw_traffic/`

- `flask_server.py`  
  Windows-side server receiving pinning reports and:
  - Resolves which **Android package** is linked to the traffic (via `ss` or `netstat` inside the rooted emulator).
  - If `RUN_FRIDA=1` is set, automatically launches **Frida** to apply the universal SSL pinning bypass.

---

## How to Run

### 1. Start the Flask server (Windows)
```powershell
# Only report (no Frida launch)
set RUN_FRIDA=0
python flask_server.py

# Report + automatically launch Frida
set RUN_FRIDA=1
python flask_server.py
```

Default listen address: `127.0.0.1:5001`.

### 2. Start mitmproxy (Ubuntu)
```bash
mitmproxy -p 8080 -s postprocesado_dlp_v3.py
```

This will:
- Capture traffic
- Dump flows into `raw_traffic/`
- Report TLS handshake errors (pinning) to Flask

### 3. Configure proxy in the Android emulator (Windows)
Inside the emulator network settings:
- **Proxy host** = IP of the Ubuntu VM  
- **Proxy port** = 8080  

Install mitmproxy’s CA certificate in the emulator or rely on **Frida** for bypass.

### 4. DLP Post-Processing
To analyze leaks:
```bash
python postprocesado_dlp_v3.py
```

Outputs:
- `dlp_results.txt` → detailed per flow  
- `summary_by_type.csv` → global summary (IMEI, DeviceID, Bearer tokens, etc.)  

---

## Example Workflow

1. An app in the emulator attempts to connect to `api.sporttia.com`.  
2. If no pinning: mitmproxy intercepts, dumps traffic → DLP detects a **Bearer token** or **QR SVG**.  
3. If pinning is present: mitmproxy fails TLS → addon reports error to Flask.  
4. Flask resolves which Android package owns the connection.  
5. With `RUN_FRIDA=1`, Flask triggers:
   ```bash
   frida --codeshare sowdust/universal-android-ssl-pinning-bypass-2 -f <PACKAGE> -U
   ```
6. Traffic becomes interceptable again and is analyzed.

---

## Flask Server Endpoints

- `POST /report_ssl_pinning`  
  Payload from mitmproxy with `host`, `sni`, `port`, `client_peer`.

- `GET /apps_with_pinning`  
  List of all reported events.

- `GET /frida_processes`  
  Shows processes detectable by Frida (`frida-ps -U -a`).

---

## Why This Architecture?

- **Separation of concerns:** Ubuntu VM for capture/mitmproxy (clean, scriptable), Windows host for instrumentation (AVD+Magisk+Frida).  
- **Compatibility:** Android Studio/AVD and Frida run more smoothly on Windows with GPU/Hyper-V.  
- **Robustness:** Linux handles certificates and routing more reliably.  
- **Scalability:** Multiple Ubuntu VMs can report to the same Flask server for distributed SSL bypass orchestration.

---

## Expected Results

- Identification of sensitive data leaks (DeviceID, IMEI, OAuth2 Bearer, QR tokens, etc).  
- Classification of apps vulnerable to MITM due to missing pinning.  
- Automated SSL bypass for apps with pinning using Frida.

---

## TODO (Future Work)

- Extend the analysis to a broader dataset (e.g., [AndroZoo](https://androzoo.uni.lu/)).  
- Automate APK installation and testing pipeline in the emulator.  
- Integrate automated app stimulation (Monkey, Selenium, etc.) to generate richer traffic.  
- Enhance DLP detection with ML classifiers for sensitive data patterns.  
- Improve SSL bypass orchestration and error recovery logic.  
- Explore integration with privacy compliance frameworks (e.g., GDPR auditing).

---

> **Note:** Adapted version for this experimental environment, with TODO list for further improvements.
