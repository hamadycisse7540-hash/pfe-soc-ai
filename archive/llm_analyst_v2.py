#!/usr/bin/env python3
"""
PFE SOC - LLM Analyst v2
Detection as Code : analyse les alertes Wazuh avec Claude
et génère automatiquement des règles de détection
"""
import json, os, time, subprocess, hashlib
import xml.etree.ElementTree as ET
from datetime import datetime
import anthropic

# ── Constantes ──────────────────────────────────────────────────────────────
ALERTS_FILE  = "/var/ossec/logs/alerts/alerts.json"
RULES_DIR    = os.path.expanduser("~/pfe_soc/github/rules/custom")
WAZUH_RULES  = "/var/ossec/etc/rules"
LOG_FILE     = os.path.expanduser("~/pfe_soc/llm_analysis.log")
MIN_LEVEL    = 8
MODEL        = "claude-sonnet-4-5"

# ── Cache anti-doublons ──────────────────────────────────────────────────────
# Clé = (rule_id Wazuh, srcip) → empêche d'analyser le même couple deux fois
seen_pairs   = set()
# Règles déjà générées par le LLM (hash du XML)
deployed_hashes = set()

client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

# ── Chargement des règles existantes au démarrage ───────────────────────────
def load_existing():
    for fname in os.listdir(WAZUH_RULES):
        if fname.startswith("llm_") and fname.endswith(".xml"):
            path = os.path.join(WAZUH_RULES, fname)
            content = open(path).read()
            deployed_hashes.add(hashlib.md5(content.encode()).hexdigest())
    print(f"  Règles LLM existantes : {len(deployed_hashes)}")

# ── Appel LLM ────────────────────────────────────────────────────────────────
def ask_llm(alert: dict) -> dict | None:
    prompt = f"""Tu es un analyste SOC expert Wazuh v4.7.5.

Alerte reçue :
{json.dumps(alert, indent=2, ensure_ascii=False)}

Réponds UNIQUEMENT avec un objet JSON valide (pas de markdown, pas de ```):
{{
  "type_attaque": "nom court",
  "severite": "CRITIQUE|HAUTE|MOYENNE|FAIBLE",
  "ip_source": "IP ou null",
  "action": "action recommandée en 1 phrase",
  "generer_regle": true,
  "regle_xml": "<rule id=\\"100020\\" level=\\"12\\"><if_sid>5716</if_sid><description>...</description><group>brute_force,</group></rule>"
}}

Règles pour le XML :
- ID entre 100020 et 100099
- Balises autorisées : if_sid, match, srcip, description, group, same_source_ip, frequency, timeframe, if_matched_sid
- PAS de balises : tactic, technique, mitre (elles causent des erreurs dans Wazuh 4.7.5)
- Si generer_regle=false, mettre regle_xml=null"""

    try:
        resp = client.messages.create(
            model=MODEL,
            max_tokens=800,
            messages=[{"role": "user", "content": prompt}]
        )
        text = resp.content[0].text.strip()
        # Nettoie si le LLM a quand même mis des backticks
        if "```" in text:
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        return json.loads(text.strip())
    except Exception as e:
        print(f"  [!] Erreur LLM : {e}")
        return None

# ── Validation XML strict Wazuh 4.7.5 ────────────────────────────────────────
FORBIDDEN_TAGS = {"tactic", "technique", "mitre"}

def validate_xml(xml_str: str) -> tuple[bool, str]:
    """Retourne (valide, message)"""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        return False, f"XML invalide : {e}"

    for elem in root.iter():
        if elem.tag in FORBIDDEN_TAGS:
            return False, f"Tag interdit : <{elem.tag}>"

    rules = root.findall(".//rule") if root.tag != "rule" else [root]
    if not rules:
        return False, "Aucune règle trouvée"

    for rule in rules:
        rid = rule.get("id", "")
        if not rid.isdigit() or not (100000 <= int(rid) <= 199999):
            return False, f"ID invalide : {rid}"
        desc = rule.find("description")
        if desc is None or not (desc.text or "").strip():
            return False, "Description manquante"

    return True, "OK"

# ── Déploiement ──────────────────────────────────────────────────────────────
def deploy(rule_xml: str, alert_type: str) -> bool:
    # Enveloppe dans un groupe si nécessaire
    if not rule_xml.strip().startswith("<group"):
        rule_xml = f'<group name="llm_generated,local,">\n{rule_xml}\n</group>'

    # Validation
    ok, msg = validate_xml(rule_xml)
    if not ok:
        print(f"  [!] Validation échouée : {msg}")
        return False

    # Anti-doublon par hash
    h = hashlib.md5(rule_xml.encode()).hexdigest()
    if h in deployed_hashes:
        print(f"  (règle identique déjà déployée — ignorée)")
        return False
    deployed_hashes.add(h)

    # Sauvegarde locale
    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"llm_{alert_type[:20]}_{ts}.xml"
    local = os.path.join(RULES_DIR, fname)
    with open(local, "w") as f:
        f.write(rule_xml)
    print(f"  Regle sauvegardee : {fname}")

    # Copie vers Wazuh
    wazuh_dest = os.path.join(WAZUH_RULES, fname)
    proc = subprocess.Popen(
        ["sudo", "tee", wazuh_dest],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    _, err = proc.communicate(input=rule_xml.encode())
    if proc.returncode != 0:
        print(f"  [!] Erreur copie Wazuh : {err.decode()}")
        return False

    # Validation par Wazuh avant redémarrage
    test = subprocess.run(
        ["sudo", "/var/ossec/bin/wazuh-analysisd", "-t"],
        capture_output=True, text=True
    )
    if "CRITICAL" in test.stderr or "ERROR" in test.stderr:
        print(f"  [!] Règle rejetée par Wazuh — suppression")
        subprocess.run(["sudo", "rm", "-f", wazuh_dest], capture_output=True)
        os.remove(local)
        deployed_hashes.discard(h)
        return False

    # Redémarre Wazuh
    subprocess.run(
        ["sudo", "systemctl", "restart", "wazuh-manager"],
        capture_output=True
    )
    print(f"  Regle deployee sur Wazuh")

    # Commit GitHub
    try:
        os.chdir(os.path.expanduser("~/pfe_soc/github"))
        subprocess.run(["git", "add", f"rules/custom/{fname}"],
                       capture_output=True)
        subprocess.run(["git", "commit", "-m",
                        f"LLM auto-rule: {alert_type} [{ts}]"],
                       capture_output=True)
        subprocess.run(["git", "push"], capture_output=True)
        print(f"  Pushee sur GitHub")
    except Exception as e:
        print(f"  [!] GitHub : {e}")

    return True

# ── Traitement d'une alerte ───────────────────────────────────────────────────
def process(alert: dict):
    rule    = alert.get("rule", {})
    level   = int(rule.get("level", 0))
    rule_id = rule.get("id", "")
    desc    = rule.get("description", "")[:50]
    srcip   = alert.get("data", {}).get("srcip", "local")

    if level < MIN_LEVEL:
        return

    # Cache anti-doublon : même règle Wazuh + même IP = ignoré
    pair = (rule_id, srcip)
    if pair in seen_pairs:
        return
    seen_pairs.add(pair)

    print(f"\n[LLM] Analyse alerte niveau {level} — {desc}")

    result = ask_llm(alert)
    if not result:
        return

    print(f"  Type      : {result.get('type_attaque','?')}")
    print(f"  Severite  : {result.get('severite','?')}")
    print(f"  IP source : {result.get('ip_source','N/A')}")
    print(f"  Action    : {result.get('action','?')}")

    # Log
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps({
            "ts": datetime.now().isoformat(),
            "rule_id": rule_id,
            "level": level,
            "analyse": result,
        }, ensure_ascii=False) + "\n")

    # Génération et déploiement de la règle
    if result.get("generer_regle") and result.get("regle_xml"):
        atype = result["type_attaque"].replace(" ", "_").lower()
        deployed = deploy(result["regle_xml"], atype)
        if not deployed:
            print(f"  (regle non deployee)")
    else:
        print(f"  (pas de nouvelle regle nécessaire)")

# ── Point d'entrée ────────────────────────────────────────────────────────────
print(f"[{datetime.now()}] LLM Analyst v2 demarre")
print(f"Surveillance : {ALERTS_FILE} | niveau >= {MIN_LEVEL}")
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
            aid = alert.get("id", "")
            if aid in seen_alerts:
                continue
            seen_alerts.add(aid)
            process(alert)
        except Exception:
            continue
