#!/usr/bin/env python3
import subprocess, time, json, re
from datetime import datetime

seen_ips = {}
COOLDOWN = 60  # 1 minute pour demo  # 5 minutes
ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
# IPs Kali connues uniquement
KALI_IPS = {"192.168.1.139", "192.168.1.140"}

print("[Nmap Watcher] Démarré - détecte uniquement les IPs Kali")

proc = subprocess.Popen(['sudo','tail','-f','/var/log/kern.log'],
    stdout=subprocess.PIPE, text=True)

for line in proc.stdout:
    if 'IPTABLES-DROP' not in line or 'IN=eth0' not in line:
        continue
    m = re.search(r'SRC=(\d+\.\d+\.\d+\.\d+)', line)
    if not m:
        continue
    srcip = m.group(1)

    # Seulement les IPs Kali connues
    if srcip not in KALI_IPS:
        continue

    # Ignore le trafic Wazuh agent (port 1514) — faux positif
    if 'DPT=1514' in line or 'SPT=1514' in line:
        continue

    # Ignore aussi les connexions SSH etablies (ACK sans SYN = pas un scan)
    if 'ACK' in line and 'SYN' not in line:
        continue
    
    # Cooldown
    now = time.time()
    if now - seen_ips.get(srcip, 0) < COOLDOWN:
        continue
    seen_ips[srcip] = now

    alert = {
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000+0200"),
        "rule": {"level": 10, "description": "Nmap scan detected via iptables",
                 "id": "100002", "groups": ["nmap_scan","reconnaissance"]},
        "agent": {"id": "001", "name": "kali", "ip": srcip},
        "manager": {"name": "ubuntu-Virtual-Machine"},
        "data": {"srcip": srcip, "protocol": "TCP"},
        "location": "/var/log/kern.log"
    }
    subprocess.run(["sudo","tee","-a", ALERTS_FILE],
        input=json.dumps(alert)+"\n", capture_output=True, text=True)
    print(f"[Nmap Watcher] Scan Kali détecté depuis {srcip}")
