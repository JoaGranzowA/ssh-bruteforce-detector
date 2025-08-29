#!/usr/bin/env python3
import re
import csv
import json
import os
from datetime import datetime
from collections import defaultdict

LOG_FILE = "/var/log/auth.log"
THRESHOLD = 5  # minimo de intentos para considerar la ip sospechosa
CSV_PATH = "detections.csv"
JSON_PATH = "detections.json"

# Regex que captura: timestamp, usuario (o invalid user <x>), IP
LINE_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*sshd.*Failed password for (?:invalid user\s+)?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# --- Geolocalización opcional (si no hay requests, cae a Unknown) ---
try:
    import requests

    def geolocate(ip: str) -> str:
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=4).json()
            if r.get("status") == "success":
                country = r.get("country", "")
                city = r.get("city", "")
                return f"{country or 'Unknown'}{(' - ' + city) if city else ''}"
            return "Unknown"
        except Exception:
            return "Unknown"

except Exception:
    def geolocate(ip: str) -> str:
        return "Unknown"

# --- Parseo del log y conteos ---
attempts_by_ip = defaultdict(int)
users_by_ip = defaultdict(set)

with open(LOG_FILE, "r", errors="ignore") as f:
    for line in f:
        m = LINE_RE.search(line)
        if not m:
            continue
        ip = m.group("ip")
        user = m.group("user")
        attempts_by_ip[ip] += 1
        users_by_ip[ip].add(user)

# Momento de la ejecución (no el del evento individual)
run_ts_utc = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

print("=== Posibles ataques de fuerza bruta detectados ===")
rows_for_csv = []
rows_for_json = []

for ip, count in sorted(attempts_by_ip.items(), key=lambda x: x[1], reverse=True):
    if count > THRESHOLD:
        print(f"[!] IP {ip} con {count} intentos fallidos")
        geo = geolocate(ip)
        rows_for_csv.append([
            run_ts_utc, ip, count, geo,
            ",".join(sorted(list(users_by_ip[ip]))[:5])
        ])
        rows_for_json.append({
            "run_ts_utc": run_ts_utc,
            "ip": ip,
            "intentos": count,
            "geo": geo,
            "usuarios_ej": sorted(list(users_by_ip[ip]))[:5]
        })

# --- Guardar CSV (append, con header si no existe) ---
csv_header = ["run_ts_utc", "ip", "intentos", "geo", "usuarios_ej"]
write_header = not os.path.exists(CSV_PATH)

with open(CSV_PATH, "a", newline="") as f:
    w = csv.writer(f)
    if write_header:
        w.writerow(csv_header)
    w.writerows(rows_for_csv)

# --- Guardar JSON (append simple: acumulamos en una lista) ---
data_json = []
if os.path.exists(JSON_PATH):
    try:
        with open(JSON_PATH, "r") as jf:
            data_json = json.load(jf)
    except Exception:
        data_json = []

data_json.extend(rows_for_json)
with open(JSON_PATH, "w") as jf:
    json.dump(data_json, jf, indent=2)

print(f"\n[+] Guardado/actualizado CSV: {CSV_PATH}")
print(f"[+] Guardado/actualizado JSON: {JSON_PATH}")
