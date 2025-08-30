# postprocesado_dlp_v3.py
# ------------------------------------------------------------
# Modo 1 (standalone):    python postprocesado_dlp_v3.py
#   -> Post-procesa ficheros de trafico_bruto/ y genera:
#      - resultados_dlp.txt
#      - resumen_por_tipo.csv
#
# Modo 2 (mitmproxy addon): mitmproxy -s postprocesado_dlp_v3.py
#   -> Registra fallos de TLS (pinning) y vuelca tráfico a trafico_bruto/
#   -> Opcional: reporta a un servidor Flask (host Windows) para coordinar Frida
# ------------------------------------------------------------

import os
import re
import csv
import json
import uuid
import datetime

# === Config común ===
CARPETA = "trafico_bruto"
SALIDA_TXT = "resultados_dlp.txt"
SALIDA_CSV = "resumen_por_tipo.csv"
os.makedirs(CARPETA, exist_ok=True)

# Endpoint Flask (en Windows host) para reportar pinning
FLASK_ENDPOINT = os.environ.get("FLASK_ENDPOINT", "http://127.0.0.1:5001/report_ssl_pinning")

# =========================
#  A) BLOQUE DLP (standalone)
# =========================
regex_dlp = {
    "IMEI": r"imei[=:]\s?\d{14,16}",
    "IMSI": r"imsi[=:]\s?\d{14,15}",
    "AndroidID": r"androidid[=:]\s?[\w-]{8,}",
    "DeviceID": r"deviceid[=:]\s?[\w-]{8,}",
    "Serial": r"serial[=:]\s?[\w-]{8,}",
    "GPS": r"lat[=:]\d{2}\.\d+.*lon[=:]-?\d{1,3}\.\d+",
    "PhoneNumber": r"phone(number)?[=:]?\s?(\+?\d{6,15})"
}

regex_http = {
    "Bearer Token": r"Authorization:\s*Bearer\s+([a-zA-Z0-9_\-\.]+)",
    "Unlockers": r"unlockers",
    "Users": r"users",
    "Payments": r"payments",
    "Cards": r"cards"
}

def run_dlp_postprocess():
    resultados = []
    resumen = {k: 0 for k in regex_dlp.keys()}
    resumen_http = {k: 0 for k in regex_http.keys()}

    for archivo in os.listdir(CARPETA):
        ruta = os.path.join(CARPETA, archivo)
        if not os.path.isfile(ruta):
            continue
        with open(ruta, "r", encoding="utf-8", errors="ignore") as f:
            texto = f.read()
            hallazgos = []
            hallazgos_http = []

            for tipo, patron in regex_dlp.items():
                matches = re.findall(patron, texto, re.IGNORECASE)
                if matches:
                    resumen[tipo] += len(matches)
                    hallazgos.append((tipo, matches))

            for tipo, patron in regex_http.items():
                matches = re.findall(patron, texto, re.IGNORECASE)
                if matches:
                    resumen_http[tipo] += len(matches)
                    hallazgos_http.append((tipo, matches))

            if hallazgos or hallazgos_http:
                resultados.append(f"📂 {archivo}")
                for tipo, matches in hallazgos:
                    for m in matches:
                        resultados.append(f"  • {tipo}: {m}")
                for tipo, matches in hallazgos_http:
                    for m in matches:
                        resultados.append(f"  • {tipo}: {m}")

    with open(SALIDA_TXT, "w", encoding="utf-8") as f:
        f.write("\n".join(resultados) if resultados else "Sin fugas detectadas en los archivos actuales.")

    with open(SALIDA_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Tipo de Dato", "Número de Detecciones"])
        for tipo, cantidad in resumen.items():
            w.writerow([tipo, cantidad])
        for tipo, cantidad in resumen_http.items():
            w.writerow([tipo, cantidad])

    print("[✔] Post-procesado DLP completado.")
    print(f"→ Detalle: {SALIDA_TXT}")
    print(f"→ Resumen: {SALIDA_CSV}")

# =========================
#  B) BLOQUE ADDONS (mitmproxy)
# =========================
def _safe_requests_post(url, json_data, timeout=2.0):
    """POST sin dependencias externas (mitmproxy trae 'requests' a veces; si no, usa urllib)."""
    try:
        import requests
        requests.post(url, json=json_data, timeout=timeout)
    except Exception:
        # Fallback simple
        try:
            import urllib.request
            req = urllib.request.Request(url, data=json.dumps(json_data).encode("utf-8"),
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=timeout)
        except Exception:
            pass  # No interrumpir el proxy

def _now_iso():
    return datetime.datetime.utcnow().isoformat() + "Z"

# Addon 1: detectar pinning (tu snippet incluido)
# --- dentro de tu postprocesado_dlp_v3.py (sección addons) ---
class SSLPinningChecker:
    """
    Detecta pinning y reporta a Flask:
    - sni/host del server
    - host+puerto destino
    - ip:puerto del cliente (emulador)
    """
    def __init__(self, report_endpoint=FLASK_ENDPOINT):
        self.report_endpoint = report_endpoint

    def error(self, flow):
        err = str(getattr(flow, "error", "")) if hasattr(flow, "error") else ""
        if "Client TLS handshake failed" in err or "does not trust the proxy's certificate" in err:
            try:
                sni = getattr(flow.server_conn, "sni", None)
                s_host = flow.request.host
                s_port = flow.request.port
                c_peer = None
                try:
                    c_peer = flow.client_conn.peername  # (ip, port) del emulador
                except Exception:
                    c_peer = "unknown"

                print(f"[!] SSL pinning contra: {sni or s_host}  | cliente={c_peer}")

                payload = {
                    "event": "ssl_pinning",
                    "sni": sni,
                    "host": s_host,
                    "port": s_port,
                    "client_peer": c_peer,
                    "time": _now_iso(),
                }
                _safe_requests_post(self.report_endpoint, payload)
            except Exception as e:
                print(f"[SSLPinningChecker] fallo al reportar: {e}")


# Addon 2: volcar tráfico legible a ficheros de texto para el DLP
class TrafficDumper:
    """
    Vuelca solicitudes/respuestas HTTP a ficheros de texto legibles en CARPETA.
    Solo para análisis didáctico/lab (no producción).
    """
    def response(self, flow):
        try:
            uid = uuid.uuid4().hex[:8]
            host = (flow.request.host or "unknown").replace(":", "_")
            path = (flow.request.path or "/").replace("/", "_")[:80]
            name = f"{host}_{uid}.txt"
            ruta = os.path.join(CARPETA, name)
            with open(ruta, "w", encoding="utf-8") as f:
                f.write(f"TIME: { _now_iso() }\n")
                f.write(f"URL: {flow.request.url}\n")
                f.write("=== REQUEST HEADERS ===\n")
                for k, v in flow.request.headers.items():
                    f.write(f"{k}: {v}\n")
                f.write("\n=== REQUEST BODY ===\n")
                try:
                    f.write(flow.request.get_text() or "")
                except Exception:
                    f.write("<binary>\n")

                f.write("\n\n=== RESPONSE STATUS ===\n")
                f.write(f"{flow.response.status_code}\n")
                f.write("\n=== RESPONSE HEADERS ===\n")
                for k, v in flow.response.headers.items():
                    f.write(f"{k}: {v}\n")
                f.write("\n=== RESPONSE BODY ===\n")
                try:
                    f.write(flow.response.get_text() or "")
                except Exception:
                    f.write("<binary>\n")
        except Exception as e:
            print(f"[TrafficDumper] Error volcando flujo: {e}")

# Si mitmproxy importa este archivo, registrará estos addons
try:
    from mitmproxy import http  # noqa: F401  - usado por type hints en tu snippet
    addons = [SSLPinningChecker(), TrafficDumper()]
except Exception:
    addons = []  # ejecución standalone

# Entry point standalone
if __name__ == "__main__":
    run_dlp_postprocess()
