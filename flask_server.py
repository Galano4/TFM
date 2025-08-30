from flask import Flask, request, jsonify
import socket, subprocess, threading, os, re

app = Flask(__name__)
RUN_FRIDA = os.environ.get("RUN_FRIDA", "0") == "1"   # set RUN_FRIDA=1 para auto-lanzar
ADB = os.environ.get("ADB", "adb")                    # ruta adb si no está en PATH

def _resolve_ips(host):
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        return ips
    except Exception:
        return []

def _run(cmd):
    # Ejecuta comando y devuelve (rc, out)
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    out, err = p.communicate()
    return p.returncode, (out or b"") + (err or b"")

def _guess_pkg_by_ip(ips, port=None):
    """
    Heurística con root en emulador:
      - usa ss -tnp para ver conexiones y PIDs
      - mapea PID -> package con dumpsys o /proc/<pid>/cmdline
    """
    # 1) sacar conexiones
    rc, outb = _run(f'{ADB} shell su -c "ss -tnp"')
    if rc != 0 or not outb:
        # fallback a netstat si existe
        rc, outb = _run(f'{ADB} shell su -c "netstat -tnp"')

    out = outb.decode("utf-8", "ignore")
    if not out:
        return None

    # 2) buscar líneas con las IPs de destino
    # formatos típicos: ESTAB 0 0 127.0.0.1:NNN <IP>:<PORT> users:(("proc",pid=1234,fd=xx))
    cand_pids = set()
    for line in out.splitlines():
        if not any(ip in line for ip in ips):
            continue
        if port and f":{port}" not in line:
            # si nos pasas puerto, filtramos más
            continue
        # extraer pid=#### si aparece
        m = re.search(r'pid=(\d+)', line)
        if m:
            cand_pids.add(m.group(1))

    # 3) mapear PID -> package
    for pid in cand_pids:
        # primero intentamos cmdline
        rc2, outb2 = _run(f'{ADB} shell su -c "cat /proc/{pid}/cmdline"')
        cmdline = outb2.decode("utf-8", "ignore").strip().replace("\x00", " ")
        pkg = None
        if cmdline:
            # típicamente el primer token contiene el package o proceso
            pkg = cmdline.split()[0]

        if not pkg:
            # fallback: dumpsys
            rc3, outb3 = _run(f'{ADB} shell dumpsys activity processes | grep -F "pid={pid}"')
            s = outb3.decode("utf-8", "ignore")
            m2 = re.search(r"ProcessRecord\{[^\}]+\s+(\S+)/", s)
            if m2:
                pkg = m2.group(1)

        if pkg:
            return pkg

    return None

def _launch_frida(pkg):
    # no bloquees Flask
    cmd = f'frida --codeshare sowdust/universal-android-ssl-pinning-bypass-2 -f {pkg} -U'
    print(f"[FRIDA] {cmd}")
    threading.Thread(target=subprocess.run, args=(cmd,), kwargs={"shell": True}).start()

@app.route("/report_ssl_pinning", methods=["POST"])
def report_ssl_pinning():
    data = request.get_json(force=True, silent=True) or {}
    host = data.get("sni") or data.get("host")
    port = data.get("port")
    ips = _resolve_ips(host) if host else []
    print(f"[FLASK] pinning→ host={host} ips={ips} port={port} from={data.get('client_peer')}")

    pkg = _guess_pkg_by_ip(ips, port=port) if ips else None
    resp = {"ok": True, "host": host, "ips": ips, "package": pkg}

    if RUN_FRIDA and pkg:
        _launch_frida(pkg)

    return jsonify(resp)

@app.route("/frida_processes", methods=["GET"])
def frida_processes():
    # Plan B: listado para cazarlos a mano o con grep
    rc, outb = _run("frida-ps -U")
    return jsonify({"rc": rc, "output": outb.decode("utf-8", "ignore")})

if __name__ == "__main__":
    # Windows host
    app.run(host="127.0.0.1", port=5001, debug=True)
