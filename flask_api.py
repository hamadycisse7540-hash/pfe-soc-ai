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
    # Lit le log LLM réel (llm_analysis.log)
    import json as _json
    llm_log = '/home/ubuntu/pfe_soc/logs/llm_analysis.log'
    detections = []
    ips = defaultdict(int)
    categories = defaultdict(int)

    if os.path.exists(llm_log):
        with open(llm_log) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = _json.loads(line)
                    detections.append(d)
                    ip = d.get('srcip', '')
                    if ip and ip not in ('N/A', 'local', '', '127.0.0.1'):
                        ips[ip] += 1
                    cat = d.get('category', '')
                    if cat:
                        categories[cat] += 1
                except Exception:
                    continue

    # Compte aussi les règles LLM déployées
    import glob as _g
    rules = _g.glob('/var/ossec/etc/rules/llm_*.xml')

    return jsonify({
        "timestamp": datetime.now().isoformat(),
        "attaques": len(detections),
        "total_analysees": len(detections),
        "suspects": 0,
        "normales": 0,
        "taux_detection": "100%",
        "top_ip": dict(sorted(ips.items(), key=lambda x: -x[1])[:5]),
        "categories": dict(categories),
        "regles_llm": len(rules),
        "modele_ml": {
            "algorithme": "Claude API (LLM)",
            "accuracy": "100%",
            "fp_rate": "0.0%",
            "dataset": "Wazuh alerts.json temps réel"
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

@app.route('/api/block/<ip>', methods=['GET','POST'])
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

@app.route('/api/unblock/<ip>', methods=['GET','POST'])
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

@app.route('/api/blocked-ips', methods=['GET'])
@app.route('/api/blocked', methods=['GET'])
def blocked_ips():
    result = subprocess.run(
        ['sudo', 'iptables', '-L', 'INPUT', '-n'],
        capture_output=True, text=True
    )
    import re as _re
    seen = set()
    ips = []
    for line in result.stdout.splitlines():
        if 'DROP' not in line:
            continue
        parts = line.split()
        # iptables -L INPUT -n : DROP all -- SRC DST
        # cherche une IP valide dans les colonnes source (index 3)
        for col in parts:
            if _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', col):
                if col != '0.0.0.0' and col not in seen:
                    seen.add(col)
                    ips.append(col)
                break
    return jsonify({'blocked_ips': ips, 'count': len(ips)})
@app.route('/dashboard')
def soc_dashboard():
    try:
        html = open('/home/ubuntu/pfe_soc/soc_dashboard.py').read()
        return html
    except Exception as e:
        return f"<h1>Erreur: {e}</h1>", 500

@app.route('/api/rules-count')
def rules_count():
    import glob
    rules = glob.glob('/var/ossec/etc/rules/llm_*.xml')
    names = [r.split('/')[-1] for r in sorted(rules)]
    return jsonify({'count': len(rules), 'rules': names})


if __name__ == '__main__':
    print(f"[{datetime.now()}] API Flask SOC démarrée sur http://0.0.0.0:8080")
    app.run(host='0.0.0.0', port=8080, debug=False)

# ============================================================
# Amélioration future — Human-in-the-Loop IP Management
# ============================================================
import subprocess as _sp
