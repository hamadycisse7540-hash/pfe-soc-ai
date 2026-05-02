#!/usr/bin/env python3
"""
PFE SOC - LLM Analyst v3
Detection as Code avec déduplication intelligente par catégorie
"""
import json, os, time, subprocess, hashlib
import xml.etree.ElementTree as ET
from datetime import datetime
import anthropic

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
RULES_DIR   = os.path.expanduser("~/pfe_soc/github/rules/custom")
WAZUH_RULES = "/var/ossec/etc/rules"
LOG_FILE    = os.path.expanduser("~/pfe_soc/llm_analysis.log")
MIN_LEVEL   = 8
MODEL       = "claude-sonnet-4-5"

# Regroupement des rule_ids par catégorie
# Toute alerte d'une même catégorie = 1 seule analyse LLM
ATTACK_CATEGORIES = {
    "brute_force_ssh": {"5710","5711","5712","5716","5720","5763","2502","40111","5760","5758","5551"},
    "nmap_scan":       {"40101","40102","1002","100002"},
    "web_attack":      {"31100","31101","31106","31151","31152","31153"},
    "auth_failure":    {"5501","5502","5503"},
    "rootcheck":       {"510","511","512"},
    "dos_attack":      {"40113","40114","1001"},
}

def get_category(rule_id: str) -> str:
    for cat, ids in ATTACK_CATEGORIES.items():
        if rule_id in ids:
            return cat
    return f"other_{rule_id}"

# Cache : (categorie, srcip) → True si déjà analysé
seen = set()
deployed_hashes = set()

client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

def load_existing():
    count = 0
    for fname in os.listdir(WAZUH_RULES):
        if fname.startswith("llm_") and fname.endswith(".xml"):
            try:
                content = open(os.path.join(WAZUH_RULES, fname)).read()
                deployed_hashes.add(hashlib.md5(content.encode()).hexdigest())
                count += 1
            except:
                pass
    if count:
        print(f"  {count} règle(s) LLM existante(s) chargée(s)")

def ask_llm(alert: dict, category: str) -> dict | None:
    prompt = f"""Tu es un analyste SOC expert Wazuh v4.7.5.

Alerte reçue (catégorie détectée : {category}) :
{json.dumps(alert, indent=2, ensure_ascii=False)}

Réponds UNIQUEMENT avec un objet JSON valide (sans markdown) :
{{
  "type_attaque": "nom court (ex: Brute Force SSH)",
  "severite": "CRITIQUE|HAUTE|MOYENNE|FAIBLE",
  "ip_source": "IP ou null",
  "action": "action en 1 phrase",
  "generer_regle": true,
  "regle_xml": "<rule id=\\"100020\\" level=\\"12\\"><if_sid>5716</if_sid><same_source_ip /><description>LLM: SSH brute force detected</description><group>brute_force,authentication_failures,</group></rule>"
}}

Contraintes XML strictes pour Wazuh 4.7.5 :
- Utilise UNIQUEMENT ces balises : if_sid, if_matched_sid, match, srcip, description, group, same_source_ip, frequency, timeframe, options
- INTERDIT : mitre, tactic, technique, pci_dss, gdpr, hipaa (causent des erreurs)
- ID entre 100020 et 100099
- Description non vide obligatoire
- Si aucune nouvelle règle utile, mettre generer_regle=false et regle_xml=null"""

    try:
        resp = client.messages.create(
            model=MODEL,
            max_tokens=600,
            messages=[{"role": "user", "content": prompt}]
        )
        text = resp.content[0].text.strip()
        if "```" in text:
            parts = text.split("```")
            text = parts[1] if len(parts) > 1 else parts[0]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text.strip())
    except Exception as e:
        print(f"  [!] Erreur LLM : {e}")
        return None

FORBIDDEN = {"mitre","tactic","technique","pci_dss","gdpr","hipaa",
             "nist_800_53","gpg13","tsc"}

def validate_xml(xml_str: str) -> tuple[bool, str]:
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        return False, f"XML invalide : {e}"
    for elem in root.iter():
        if elem.tag in FORBIDDEN:
            return False, f"Tag interdit : <{elem.tag}>"
    rules = root.findall(".//rule") if root.tag != "rule" else [root]
    for rule in rules:
        rid = rule.get("id","")
        if not rid.isdigit() or not (100000 <= int(rid) <= 199999):
            return False, f"ID invalide : {rid}"
        desc = rule.find("description")
        if desc is None or not (desc.text or "").strip():
            return False, "Description manquante"
    return True, "OK"

def deploy(rule_xml: str, category: str) -> bool:
    if not rule_xml.strip().startswith("<group"):
        rule_xml = f'<group name="llm_generated,local,">\n{rule_xml}\n</group>'

    ok, msg = validate_xml(rule_xml)
    if not ok:
        print(f"  [!] XML rejeté : {msg}")
        return False

    h = hashlib.md5(rule_xml.encode()).hexdigest()
    if h in deployed_hashes:
        print(f"  (règle identique déjà déployée)")
        return False
    deployed_hashes.add(h)

    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"llm_{category}_{ts}.xml"
    local = os.path.join(RULES_DIR, fname)

    with open(local, "w") as f:
        f.write(rule_xml)

    wazuh_dest = os.path.join(WAZUH_RULES, fname)
    proc = subprocess.Popen(
        ["sudo", "tee", wazuh_dest],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    _, err = proc.communicate(input=rule_xml.encode())
    if proc.returncode != 0:
        print(f"  [!] Erreur copie : {err.decode()}")
        return False

    # Test Wazuh avant redémarrage
    test = subprocess.run(
        ["sudo", "/var/ossec/bin/wazuh-analysisd", "-t"],
        capture_output=True, text=True
    )
    if "CRITICAL" in test.stderr or "CRITICAL" in test.stdout:
        print(f"  [!] Rejetée par Wazuh — supprimée")
        subprocess.run(["sudo","rm","-f",wazuh_dest], capture_output=True)
        os.remove(local)
        deployed_hashes.discard(h)
        return False

    subprocess.run(["sudo","systemctl","restart","wazuh-manager"],
                   capture_output=True)
    print(f"  Regle deployee : {fname}")

    # Push GitHub
    try:
        os.chdir(os.path.expanduser("~/pfe_soc/github"))
        subprocess.run(["git","add",f"rules/custom/{fname}"], capture_output=True)
        subprocess.run(["git","commit","-m",
            f"LLM auto-rule: {category} [{ts}]"], capture_output=True)
        subprocess.run(["git","push"], capture_output=True)
        print(f"  Pushee sur GitHub")
    except Exception as e:
        print(f"  [!] GitHub : {e}")

    return True

def process(alert: dict):
    rule    = alert.get("rule", {})
    level   = int(rule.get("level", 0))
    rule_id = rule.get("id", "")
    desc    = rule.get("description", "")[:50]
    srcip   = alert.get("data", {}).get("srcip", "local")

    if level < MIN_LEVEL:
        return

    category = get_category(rule_id)
    key = (category, srcip)

    if key in seen:
        return  # Silence total pour les doublons
    seen.add(key)

    print(f"\n[LLM] Analyse alerte niveau {level} — {desc}")
    print(f"  Categorie : {category}")

    result = ask_llm(alert, category)
    if not result:
        return

    print(f"  Type      : {result.get('type_attaque','?')}")
    print(f"  Severite  : {result.get('severite','?')}")
    print(f"  IP source : {result.get('ip_source','N/A')}")
    print(f"  Action    : {result.get('action','?')}")

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps({
            "ts": datetime.now().isoformat(),
            "category": category,
            "rule_id": rule_id,
            "level": level,
            "analyse": {
                "type_attaque": result.get("type_attaque"),
                "severite": result.get("severite"),
                "ip_source": result.get("ip_source"),
                "action": result.get("action"),
            },
            "rule_generated": result.get("generer_regle", False)
        }, ensure_ascii=False) + "\n")

    if result.get("generer_regle") and result.get("regle_xml"):
        print(f"  Generation regle XML...")
        deploy(result["regle_xml"], category)
    else:
        print(f"  (pas de nouvelle regle nécessaire)")

# ── Main ─────────────────────────────────────────────────────────────────────
print(f"[{datetime.now()}] LLM Analyst v3 demarre")
print(f"Surveillance : {ALERTS_FILE} | niveau >= {MIN_LEVEL}")
print(f"Categories : {list(ATTACK_CATEGORIES.keys())}")
load_existing()
print()

seen_alerts = set()
with open(ALERTS_FILE, "r") as f:
    f.seek(0, 2)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.3)
            continue
        try:
            alert = json.loads(line.strip())
            aid = alert.get("id","")
            if aid in seen_alerts:
                continue
            seen_alerts.add(aid)
            process(alert)
        except Exception:
            continue
