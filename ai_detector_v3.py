import json, time, os, warnings, csv
from datetime import datetime
from collections import defaultdict
warnings.filterwarnings('ignore')

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
LOG_FILE    = os.path.expanduser("~/pfe_soc/ai_detections.log")

# Compteurs par IP pour détection comportementale
seen_sigs = set()

ip_stats = defaultdict(lambda: {
    'fails': 0, 'levels': [], 'first_seen': None, 'last_seen': None
})

BRUTE_RULES   = {'5710','5711','5712','5713','5716','5720','5503'}
CRITICAL_LVLS = {10, 11, 12, 13, 14, 15}
BRUTE_GROUPS  = {'authentication_failures','brute_force',
                 'authentication_failed','sshd'}


def make_signature(alert):
    rule_id = alert.get("rule", {}).get("id", "")
    agent   = alert.get("agent", {}).get("name", "")
    src     = alert.get("data",  {}).get("srcip", "local")
    ts      = alert.get("timestamp", "")[:16]
    return f"{rule_id}:{agent}:{src}:{ts}"

def classify(alert):
    rule   = alert.get('rule', {})
    data   = alert.get('data', {})
    level  = int(rule.get('level', 0))
    rid    = str(rule.get('id', ''))
    groups = set(rule.get('groups', []))
    src    = data.get('srcip', 'N/A')
    desc   = rule.get('description', '').lower()

    # Met à jour les stats par IP
    now = datetime.now()
    s = ip_stats[src]
    s['fails'] += 1
    s['levels'].append(level)
    if not s['first_seen']:
        s['first_seen'] = now
    s['last_seen'] = now

    # Fenêtre temporelle (2 minutes)
    window = (s['last_seen'] - s['first_seen']).seconds if s['first_seen'] else 0
    rate   = s['fails'] / max(window, 1) * 60  # échecs/minute

    # Critères de détection IA
    is_brute_rule  = rid in BRUTE_RULES
    is_brute_group = bool(groups & BRUTE_GROUPS)
    is_brute_desc  = any(w in desc for w in
                        ['brute','patator','authentication fail',
                         'multiple auth','password'])
    is_high_rate   = rate > 5  # plus de 5 échecs/min
    is_accumulated = s['fails'] >= 8
    is_critical    = level in CRITICAL_LVLS

    score = (int(is_brute_rule)  * 3 +
             int(is_brute_group) * 2 +
             int(is_brute_desc)  * 2 +
             int(is_high_rate)   * 3 +
             int(is_accumulated) * 2 +
             int(is_critical)    * 2)

    confidence = min(score / 10.0, 1.0)

    if score >= 5:
        return "ATTAQUE", confidence, score, src, s['fails'], rate
    elif score >= 3:
        return "SUSPECT", confidence, score, src, s['fails'], rate
    else:
        return "normal",  confidence, score, src, s['fails'], rate

print(f"[{datetime.now()}] IA Detector v3 HYBRID demarre")
print(f"Surveillance : {ALERTS_FILE}\n")

stats = {'total':0, 'attacks':0, 'suspects':0, 'normal':0}

with open(ALERTS_FILE, 'r') as f:
    f.seek(0, 2)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.2)
            continue
        try:
            alert = json.loads(line.strip())
            sig = make_signature(alert)
            if sig in seen_sigs:
                continue
            seen_sigs.add(sig)
            level = int(alert.get('rule',{}).get('level', 0))
            if level < 3:
                continue

            label, conf, score, src, fails, rate = classify(alert)
            stats['total'] += 1
            if label == 'ATTAQUE':
                stats['attacks'] += 1
            elif label == 'SUSPECT':
                stats['suspects'] += 1
            else:
                stats['normal'] += 1

            agent = alert.get('agent',{}).get('name','manager')
            desc  = alert.get('rule',{}).get('description','')[:45]
            tag   = f"[{label}]"

            if label != 'normal':
                msg = (f"[{datetime.now().strftime('%H:%M:%S')}] "
                       f"{tag:10} conf={conf:.2f} score={score} "
                       f"lvl={level} fails={fails} rate={rate:.1f}/min "
                       f"src={src} | {desc}")
                print(msg)
                with open(LOG_FILE, 'a') as lf:
                    lf.write(msg + '\n')

            if stats['total'] % 20 == 0:
                print(f"  Stats: {stats} | IPs trackées: {len(ip_stats)}")
        except Exception:
            continue
