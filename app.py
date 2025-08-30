from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

@app.route('/bypass', methods=['POST'])
def bypass():
    data = request.json
    package = data.get("package")
    if not package:
        return jsonify({"error": "No package specified"}), 400
    # Example: Launch frida bypass
    cmd = [
        "frida",
        "--codeshare", "sowdust/universal-android-ssl-pinning-bypass-2",
        "-f", package, "-U"
    ]
    subprocess.Popen(cmd)
    return jsonify({"status": "Bypass launched", "package": package})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
