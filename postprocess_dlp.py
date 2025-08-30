import re, os

patterns = {
    "DeviceID": re.compile(r"\b[0-9a-f]{16}\b", re.I),
    "Bearer": re.compile(r"Authorization:\s*Bearer\s+[A-Za-z0-9\-\._]+")
}

def analyze_file(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = f.read()
    results = {}
    for name, pattern in patterns.items():
        results[name] = pattern.findall(data)
    return results
