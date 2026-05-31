#!/usr/bin/env python3
import json, time, joblib, os
import numpy as np
from datetime import datetime

MODEL_PATH    = os.path.expanduser("~/pfe_soc/models/model_rf.pkl")
FEATURES_PATH = os.path.expanduser("~/pfe_soc/models/features.json")
ALERTS_FILE   = "/var/ossec/logs/alerts/alerts.json"
LOG_FILE      = os.path.expanduser("~/pfe_soc/ai_detections.log")

model    = joblib.load(MODEL_PATH)
features = json.load(open(FEATURES_PATH))
print(f"[{datetime.now()}] IA Detector demarre - {len(features)} features")

def extract_features(alert):
    data   = alert.get("data", {})
    rule   = alert.get("rule", {})
    level  = int(rule.get("level", 0))
    groups = ",".join(rule.get("groups", []))
    is_bf  = "brute" in groups or "authentication" in groups
    return [
        float(data.get("duration", 1000 if not is_bf else 500)),
        float(data.get("packets",  10   if not is_bf else 25)),
        float(data.get("bwd_packets", 5 if not is_bf else 20)),
        float(data.get("bytes_s",  1000 if not is_bf else 80000)),
        float(data.get("pps",      10   if not is_bf else 500)),
        80.0  if is_bf else 500.0,
        60.0  if is_bf else 400.0,
        float(level) if is_bf else 1.0,
        float(level),
        2.0 if level >= 5 else 0.0,
        80.0  if is_bf else 500.0,
        60.0  if is_bf else 400.0,
        300.0 if is_bf else 30.0,
        200.0 if is_bf else 20.0,
        20.0  if is_bf else 50.0,
        150.0 if is_bf else 1000.0,
        70.0  if is_bf else 450.0,
        20.0  if is_bf else 150.0,
    ]

stats = {"total": 0, "attacks": 0, "normal": 0}
with open(ALERTS_FILE, "r") as f:
    f.seek(0, 2)
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
            X     = np.array([extract_features(alert)])
            pred  = model.predict(X)[0]
            proba = model.predict_proba(X)[0][1]
            stats["total"] += 1
            if pred == 1:
                stats["attacks"] += 1
            else:
                stats["normal"] += 1
            agent = alert.get("agent", {}).get("name", "manager")
            src   = alert.get("data",  {}).get("srcip", "N/A")
            desc  = alert.get("rule",  {}).get("description", "")[:50]
            tag   = "[ATTAQUE]" if pred == 1 else "[normal] "
            msg   = (f"[{datetime.now().strftime('%H:%M:%S')}] {tag} "
                     f"conf={proba:.2f} lvl={level} "
                     f"agent={agent} src={src} | {desc}")
            print(msg)
            with open(LOG_FILE, "a") as lf:
                lf.write(msg + "\n")
            if stats["total"] % 10 == 0:
                print(f"  Stats: {stats}")
        except Exception:
            continue
