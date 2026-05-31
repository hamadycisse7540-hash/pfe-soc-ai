#!/usr/bin/env python3
"""
Injection d'alertes pour attaques non générables depuis Kali
(DoS et Privilege Escalation)
"""
import json, subprocess, time
from datetime import datetime

def inject(rule_id, level, description, srcip, groups, extra=None):
    alert = {
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000+0200"),
        "rule": {"level": level, "description": description,
                 "id": rule_id, "groups": groups},
        "agent": {"id": "001", "name": "kali", "ip": srcip},
        "manager": {"name": "ubuntu-Virtual-Machine"},
        "data": {"srcip": srcip},
        "location": "/var/log/auth.log"
    }
    if extra:
        alert["data"].update(extra)
    r = subprocess.run(
        ["sudo", "tee", "-a", "/var/ossec/logs/alerts/alerts.json"],
        input=json.dumps(alert) + "\n",
        capture_output=True, text=True
    )
    status = "OK" if r.returncode == 0 else "ERR"
    print(f"  [{status}] Niv.{level} — {description[:50]} | IP={srcip}")
    return r.returncode == 0

def wait_wazuh():
    print("  Attends que Wazuh soit stable...")
    for _ in range(30):
        r = subprocess.run(
            ["sudo", "systemctl", "is-active", "wazuh-manager"],
            capture_output=True, text=True
        )
        if r.stdout.strip() == "active":
            time.sleep(5)
            return True
        time.sleep(2)
    return False

print("=== Injection alertes démo (DoS + Privilege Escalation) ===\n")

wait_wazuh()

# Nmap optionnel (si Kali dans le cooldown nmap_watcher)
import sys
if '--with-nmap' in sys.argv:
    print("0. Nmap Scan (192.168.1.139) [forcé]...")
    inject("100002", 10, "Nmap scan detected via iptables",
           "192.168.1.139", ["nmap_scan","reconnaissance"])
    print("  LLM analyse en cours... (attends ~30s)")
    time.sleep(35)
    wait_wazuh()
    time.sleep(5)

print("1. DoS Attack (192.168.1.250)...")
inject("40113", 10, "DoS attack detected - SYN flood",
       "192.168.1.250", ["dos_attack"])
print("  LLM analyse en cours... (attends ~30s)")
time.sleep(35)
wait_wazuh()
time.sleep(5)

print("\n2. Privilege Escalation (192.168.1.139)...")
inject("5402", 12, "Successful sudo to ROOT executed",
       "192.168.1.139", ["syslog", "sudo"],
       {"srcuser": "hacker", "dstuser": "root", "command": "/bin/bash"})
print("  LLM analyse en cours... (attends ~30s)")
time.sleep(35)
wait_wazuh()

print("\n=== Injection terminée ===")
