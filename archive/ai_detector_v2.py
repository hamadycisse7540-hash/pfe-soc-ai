import json, time, joblib, os, warnings
import numpy as np, pandas as pd
from datetime import datetime
warnings.filterwarnings('ignore')

MODEL    = joblib.load(os.path.expanduser("~/pfe_soc/models/model_v2.pkl"))
FEATURES = json.load(open(os.path.expanduser("~/pfe_soc/models/features_v2.json")))
LOG      = os.path.expanduser("~/pfe_soc/ai_detections.log")
ip_fails = {}

print(f"[{datetime.now()}] IA Detector v2 - {len(FEATURES)} features\n")

def extract(alert):
    data   = alert.get("data", {})
    rule   = alert.get("rule", {})
    level  = int(rule.get("level", 0))
    groups = " ".join(rule.get("groups", []))
    src    = data.get("srcip", "")
    is_bf  = int("brute" in groups or "patator" in groups or
                  "authentication_fail" in groups)
    ip_fails[src] = ip_fails.get(src, 0) + (1 if level >= 5 else 0)
    fails  = ip_fails.get(src, 0)
    return {
        'Flow Duration':          500.0  if is_bf else 5000.0,
        'Total Fwd Packets':      25.0   if is_bf else 8.0,
        'Total Backward Packets': 20.0   if is_bf else 6.0,
        'Flow Bytes/s':           80000.0 if is_bf else 2000.0,
        'Flow Packets/s':         500.0  if is_bf else 20.0,
        'SYN Flag Count':         float(level) if is_bf else 1.0,
        'ACK Flag Count':         float(level),
        'PSH Flag Count':         float(level) if is_bf else 0.0,
        'RST Flag Count':         2.0    if is_bf else 0.0,
        'Fwd Packets/s':          300.0  if is_bf else 15.0,
        'Bwd Packets/s':          200.0  if is_bf else 10.0,
        'rule_level':             float(level),
        'is_brute':               float(is_bf),
        'fail_count':             float(min(fails, 50)),
    }

with open("/var/ossec/logs/alerts/alerts.json", "r") as f:
    f.seek(0, 2)
    stats = {"total":0, "attacks":0, "normal":0}
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.3)
            continue
        try:
            alert = json.loads(line.strip())
            level = int(alert.get("rule", {}).get("level", 0))
            if level < 3:
                continue
            feat = extract(alert)
            X = pd.DataFrame([feat])[FEATURES]
            pred  = MODEL.predict(X)[0]
            proba = MODEL.predict_proba(X)[0][1]
            stats["total"] += 1
            tag = "[ATTAQUE]" if pred==1 else "[normal] "
            if pred == 1:
                stats["attacks"] += 1
            else:
                stats["normal"] += 1
            src   = alert.get("data",{}).get("srcip","N/A")
            desc  = alert.get("rule",{}).get("description","")[:45]
            msg = (f"[{datetime.now().strftime('%H:%M:%S')}] {tag} "
                   f"conf={proba:.2f} lvl={level} src={src} | {desc}")
            print(msg)
            with open(LOG,"a") as lf:
                lf.write(msg+"\n")
            if stats["total"] % 10 == 0:
                print(f"  >>> Stats: {stats}")
        except Exception:
            continue
