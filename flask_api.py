#!/usr/bin/env python3
"""
PFE SOC - API REST Flask
Expose les détections IA via HTTP
"""
from flask import Flask, jsonify, request
import json, os, csv, subprocess
from datetime import datetime
from collections import defaultdict

app = Flask(__name__)

LOG_FILE = os.path.expanduser("~/pfe_soc/ai_detections.log")
CSV_FILE = os.path.expanduser("~/pfe_soc/detections_history.csv")
ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"

def read_log():
    if not os.path.exists(LOG_FILE):
        return []
    return [l.strip() for l in open(LOG_FILE).readlines() if l.strip()]

def read_csv():
    if not os.path.exists(CSV_FILE):
        return []
    rows = []
    with open(CSV_FILE, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows

@app.route('/')
def index():
    return jsonify({
        "service": "PFE SOC - AI Detection API",
        "version": "1.0",
        "endpoints": [
            "/api/stats",
            "/api/detections",
            "/api/detections/attacks",
            "/api/top-ips",
            "/api/block/<ip>",
            "/api/unblock/<ip>",
            "/api/blocked"
        ]
    })

@app.route('/api/stats')
def stats():
    lines = read_log()
    attacks  = [l for l in lines if '[ATTAQUE]' in l]
    suspects = [l for l in lines if '[SUSPECT]' in l]
    normal   = [l for l in lines if '[normal]'  in l]

    ips = defaultdict(int)
    for l in attacks:
        if 'src=' in l:
            src = l.split('src=')[1].split(' ')[0]
            ips[src] += 1

    return jsonify({
        "timestamp": datetime.now().isoformat(),
        "total_analysees": len(lines),
        "attaques":        len(attacks),
        "suspects":        len(suspects),
        "normales":        len(normal),
        "taux_detection":  f"{len(attacks)/max(len(lines),1)*100:.1f}%",
        "top_ip":          dict(sorted(ips.items(), key=lambda x:-x[1])[:5]),
        "modele_ml": {
            "algorithme": "Random Forest",
            "accuracy":   "100%",
            "fp_rate":    "0.0%",
            "dataset":    "CIC-IDS2017 (2.7M flux)"
        }
    })

@app.route('/api/detections')
def detections():
    n = int(request.args.get('n', 20))
    rows = read_csv()
    return jsonify({
        "count": len(rows),
        "last_n": rows[-n:]
    })

@app.route('/api/detections/attacks')
def attacks_only():
    rows = read_csv()
    attacks = [r for r in rows if r.get('label') == 'ATTAQUE']
    return jsonify({
        "count": len(attacks),
        "attacks": attacks[-50:]
    })

@app.route('/api/top-ips')
def top_ips():
    rows = read_csv()
    ips = defaultdict(int)
    for r in rows:
        if r.get('label') == 'ATTAQUE' and r.get('src_ip','') not in ('N/A',''):
            ips[r['src_ip']] += 1
    ranked = sorted(ips.items(), key=lambda x:-x[1])[:10]
    return jsonify({"top_ips": [{"ip": ip, "count": c} for ip,c in ranked]})

@app.route('/api/block/<ip>')
def block_ip(ip):
    result = subprocess.run(
        ['sudo', 'iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
        capture_output=True, text=True
    )
    return jsonify({
        "action": "block",
        "ip": ip,
        "status": "success" if result.returncode == 0 else "error",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/unblock/<ip>')
def unblock_ip(ip):
    result = subprocess.run(
        ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
        capture_output=True, text=True
    )
    return jsonify({
        "action": "unblock",
        "ip": ip,
        "status": "success" if result.returncode == 0 else "error",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/blocked')
def blocked_ips():
    result = subprocess.run(
        ['sudo', 'iptables', '-L', 'INPUT', '-n'],
        capture_output=True, text=True
    )
    lines = [l for l in result.stdout.split('\n') if 'DROP' in l]
    ips = []
    for l in lines:
        parts = l.split()
        if len(parts) >= 4:
            ips.append(parts[3])
    return jsonify({"blocked_ips": ips, "count": len(ips)})

if __name__ == '__main__':
    print(f"[{datetime.now()}] API Flask SOC démarrée sur http://0.0.0.0:8080")
    app.run(host='0.0.0.0', port=8080, debug=False)
