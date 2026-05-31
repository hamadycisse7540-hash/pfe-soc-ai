from flask import Flask, jsonify, request
import sqlite3, json, subprocess, csv, io, threading, time, os
from datetime import datetime

app = Flask(__name__)
DB = "/home/ubuntu/pfe_soc/soc_detections.db"
ALERTS = "/var/ossec/logs/alerts/alerts.json"

def init_db():
    c = sqlite3.connect(DB)
    c.execute('''CREATE TABLE IF NOT EXISTS detections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, category TEXT, attack_type TEXT,
        severity TEXT, srcip TEXT, rule_id TEXT,
        level INTEGER, description TEXT, action TEXT, rule_file TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY, reason TEXT, blocked_at TEXT)''')
    c.commit(); c.close()

def save_det(d):
    try:
        c = sqlite3.connect(DB)
        c.execute('''INSERT INTO detections
            (timestamp,category,attack_type,severity,srcip,rule_id,level,description,action,rule_file)
            VALUES (?,?,?,?,?,?,?,?,?,?)''',
            (d.get('timestamp',datetime.now().isoformat()),
             d.get('category',''), d.get('attack_type',''),
             d.get('severity',''), d.get('srcip',''),
             d.get('rule_id',''), int(d.get('level',0)),
             d.get('description',''), d.get('action',''), d.get('rule_file','')))
        c.commit(); c.close()
    except: pass

def stats():
    c = sqlite3.connect(DB); r = {}
    r['total'] = c.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
    r['unique_ips'] = c.execute("SELECT COUNT(DISTINCT srcip) FROM detections WHERE srcip!=''").fetchone()[0]
    r['blocked'] = c.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
    r['by_category'] = [{"k":x[0],"v":x[1]} for x in c.execute("SELECT category,COUNT(*) FROM detections GROUP BY category ORDER BY 2 DESC").fetchall()]
    r['top_ips'] = [{"ip":x[0],"count":x[1]} for x in c.execute("SELECT srcip,COUNT(*) FROM detections WHERE srcip!='' GROUP BY srcip ORDER BY 2 DESC LIMIT 10").fetchall()]
    r['by_severity'] = [{"k":x[0],"v":x[1]} for x in c.execute("SELECT severity,COUNT(*) FROM detections WHERE severity!='' GROUP BY severity").fetchall()]
    r['recent'] = [{"ts":x[0],"cat":x[1],"type":x[2],"sev":x[3],"ip":x[4],"action":x[5],"file":x[6]} for x in c.execute("SELECT timestamp,category,attack_type,severity,srcip,action,rule_file FROM detections ORDER BY id DESC LIMIT 30").fetchall()]
    r['blocked_list'] = [{"ip":x[0],"reason":x[1],"at":x[2]} for x in c.execute("SELECT ip,reason,blocked_at FROM blocked_ips ORDER BY blocked_at DESC").fetchall()]
    llm = [f for f in sorted(os.listdir("/var/ossec/etc/rules/")) if f.startswith('llm_') and f.endswith('.xml')] if os.path.exists("/var/ossec/etc/rules/") else []
    r['llm_rules'] = llm; r['rules_count'] = len(llm)
    c.close(); return r

@app.route('/api/stats')
def api_stats():
    return jsonify(stats())

@app.route('/api/block', methods=['POST'])
def block():
    ip = request.get_json().get('ip','').strip()
    if not ip: return jsonify({"ok":False,"msg":"IP required"}),400
    try:
        subprocess.run(['sudo','iptables','-I','INPUT','-s',ip,'-j','DROP'],check=True,capture_output=True)
        c = sqlite3.connect(DB)
        c.execute("INSERT OR REPLACE INTO blocked_ips VALUES (?,?,?)",(ip,'Dashboard',datetime.now().isoformat()))
        c.commit(); c.close()
        return jsonify({"ok":True,"msg":f"IP {ip} bloquee"})
    except Exception as e: return jsonify({"ok":False,"msg":str(e)})

@app.route('/api/unblock/<ip>', methods=['DELETE'])
def unblock(ip):
    subprocess.run(['sudo','iptables','-D','INPUT','-s',ip,'-j','DROP'],capture_output=True)
    c = sqlite3.connect(DB); c.execute("DELETE FROM blocked_ips WHERE ip=?",(ip,)); c.commit(); c.close()
    return jsonify({"ok":True})

@app.route('/api/export/csv')
def export():
    c = sqlite3.connect(DB)
    rows = c.execute("SELECT * FROM detections ORDER BY id DESC").fetchall(); c.close()
    out = io.StringIO()
    csv.writer(out).writerows([['id','timestamp','category','attack_type','severity','srcip','rule_id','level','description','action','rule_file']]+list(rows))
    out.seek(0)
    return app.response_class(out.getvalue(),mimetype='text/csv',
        headers={"Content-Disposition":f"attachment;filename=soc_{datetime.now().strftime('%Y%m%d')}.csv"})

@app.route('/api/ingest', methods=['POST'])
def ingest():
    save_det(request.get_json()); return jsonify({"ok":True})

def sync():
    last = 0
    while True:
        try:
            if os.path.exists(ALERTS):
                sz = os.path.getsize(ALERTS)
                if sz < last: last = 0
                if sz > last:
                    with open(ALERTS) as f:
                        f.seek(last)
                        for line in f:
                            try:
                                a = json.loads(line.strip())
                                lvl = int(a.get('rule',{}).get('level',0))
                                ip = a.get('data',{}).get('srcip','')
                                if lvl >= 10 and ip and ip not in ('127.0.0.1',''):
                                    save_det({'timestamp':a.get('timestamp',''),'srcip':ip,
                                        'rule_id':a.get('rule',{}).get('id',''),'level':lvl,
                                        'description':a.get('rule',{}).get('description',''),
                                        'category':'','attack_type':'','severity':'','action':'','rule_file':''})
                            except: pass
                    last = sz
        except: pass
        time.sleep(3)

if __name__=='__main__':
    init_db()
    threading.Thread(target=sync,daemon=True).start()
    print("API sur http://0.0.0.0:9000")
    app.run(host='0.0.0.0',port=9000,debug=False)
