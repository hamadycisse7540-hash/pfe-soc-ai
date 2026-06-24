#!/usr/bin/env python3
"""
PFE SOC - LLM Analyst v3 FINAL
Detection as Code : LLM analyse, templates XML valides pour Wazuh 4.7.5
"""
import json, os, time, subprocess, hashlib
import xml.etree.ElementTree as ET
from datetime import datetime
import anthropic
try:
    from report_sender import send_attack_report
    EMAIL_ENABLED = True
except Exception as e:
    EMAIL_ENABLED = False
    print(f"Email désactivé: {e}")

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
RULES_DIR   = os.path.expanduser("~/pfe_soc/rules/custom")
WAZUH_RULES = "/var/ossec/etc/rules"
LOG_FILE    = os.path.expanduser("~/pfe_soc/logs/llm_analysis.log")
MIN_LEVEL   = 8
INACTIVITY_TIMEOUT = 300  # 5 minutes sans alerte → pause
MODEL       = "claude-sonnet-4-5"

# Compteur persistant pour IDs uniques
_ID_FILE = os.path.expanduser("~/pfe_soc/.rule_id_counter")

def next_rule_id():
    """ID unique persistant entre les redémarrages"""
    try:
        current = int(open(_ID_FILE).read().strip())
    except:
        current = 100050
    next_id = current + 1
    if next_id > 100099:
        next_id = 100050
    with open(_ID_FILE, 'w') as f:
        f.write(str(next_id))
    return current

# Cache anti-doublons : (categorie, srcip) — persistant sur disque
SEEN_FILE = os.path.expanduser("~/pfe_soc/.seen_categories.json")

def load_seen():
    """Charge le cache depuis le disque au démarrage."""
    try:
        data = json.load(open(SEEN_FILE))
        return set(tuple(x) for x in data)
    except:
        return set()

def save_seen(seen_set):
    """Sauvegarde le cache sur disque."""
    try:
        json.dump(list(seen_set), open(SEEN_FILE, 'w'))
    except:
        pass

seen = load_seen()
deployed_hashes = set()

ATTACK_CATEGORIES = {
    # SSH — echecs individuels et brute force
    "brute_force_ssh":     {"5710","5711","5712","5716","5720","5763","2502",
                            "40111","5760","5758","5551",
                            "100003","100010","100009",
                            "5501","5502","5503","100007"},  # PAM fusionne avec SSH brute force
    # Scan reseau — iptables DROP
    "nmap_scan":           {"40101","40102","1002","100002"},  # 100050+ = regles LLM, pas incluses
    # Attaques web Apache
    "web_attack":          {"31100","31101","31106","31151","31152","31153",
                            "31154","31155","31103","31104",
                            "100004","100005"},
    # Rootcheck / intégrité
    "rootcheck":           {"510","511","512"},
    # DoS / DDoS
    "dos_attack":          {"40113","40114","1001","100052"},
    # Escalade de privileges (sudo root, new user)
    "privilege_escalation":{"5402","5403","5404","5405",
                            "100006","100008"},
}

# Templates XML PRÉ-VALIDÉS par Wazuh 4.7.5
# Le LLM choisit le template et fournit les valeurs — pas le XML
TEMPLATES = {
    "brute_force_ssh": """<group name="llm_generated,local,syslog,sshd,">
<rule id="{id}" level="{level}" frequency="8" timeframe="120">
  <if_matched_sid>{parent_sid}</if_matched_sid>
  <same_source_ip />
  <description>{description}</description>
  <mitre><id>T1110</id></mitre>
  <group>brute_force,authentication_failures,pci_dss_11.4,gdpr_IV_35.7.d,</group>
</rule>
</group>""",

    "nmap_scan": """<group name="llm_generated,local,syslog,">
<rule id="{id}" level="{level}">
  <if_sid>{parent_sid}</if_sid>
  <match>IPTABLES-DROP</match>
  <description>{description}</description>
  <mitre><id>T1046</id></mitre>
  <group>scan_detection,reconnaissance,pci_dss_11.4,</group>
</rule>
</group>""",

    "auth_failure": """<group name="llm_generated,local,syslog,">
<rule id="{id}" level="{level}" frequency="5" timeframe="60">
  <if_matched_sid>{parent_sid}</if_matched_sid>
  <same_source_ip />
  <description>{description}</description>
  <mitre><id>T1078</id></mitre>
  <group>authentication_failed,pci_dss_10.2.4,</group>
</rule>
</group>""",

    "web_attack": """<group name="llm_generated,local,web,apache,">
<rule id="{id}" level="{level}">
  <if_sid>{parent_sid}</if_sid>
  <match>nikto|sqlmap|UNION SELECT|script</match>
  <description>{description}</description>
  <mitre><id>T1190</id></mitre>
  <group>web_attack,pci_dss_6.5,gdpr_IV_35.7.d,</group>
</rule>
</group>""",

    "dos_attack": """<group name="llm_generated,local,syslog,">
<rule id="{id}" level="{level}" frequency="10" timeframe="30">
  <if_matched_sid>{parent_sid}</if_matched_sid>
  <same_source_ip />
  <description>{description}</description>
  <mitre><id>T1498</id></mitre>
  <group>dos_attack,pci_dss_11.4,</group>
</rule>
</group>""",

    "privilege_escalation": """<group name="llm_generated,local,syslog,sudo,">
<rule id="{id}" level="{level}">
  <if_sid>{parent_sid}</if_sid>
  <match>sudo|root|NOPASSWD</match>
  <description>{description}</description>
  <mitre><id>T1548.003</id></mitre>
  <group>privilege_escalation,pci_dss_10.2.5,gdpr_IV_32.2,</group>
</rule>
</group>""",

    "rootcheck": """<group name="llm_generated,local,rootcheck,">
<rule id="{id}" level="{level}">
  <if_sid>{parent_sid}</if_sid>
  <description>{description}</description>
  <mitre><id>T1547</id></mitre>
  <group>rootcheck,pci_dss_11.4,</group>
</rule>
</group>""",

    "default": """<group name="llm_generated,local,">
<rule id="{id}" level="{level}">
  <if_sid>{parent_sid}</if_sid>
  <description>{description}</description>
  <mitre><id>T1059</id></mitre>
  <group>llm_detected,</group>
</rule>
</group>""",
}

client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

def get_category(rule_id: str) -> str:
    for cat, ids in ATTACK_CATEGORIES.items():
        if rule_id in ids:
            return cat
    return "default"

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
        print(f"  {count} règle(s) LLM existante(s)")

def ask_llm(alert: dict, category: str) -> dict | None:
    """
    Le LLM fait UNIQUEMENT l'analyse — pas le XML.
    Il retourne : type, sévérité, action, niveau suggéré, sid parent.
    """
    prompt = f"""Tu es un analyste SOC. Analyse cette alerte Wazuh et réponds en JSON pur (sans markdown).

Alerte :
{json.dumps(alert, indent=2, ensure_ascii=False)}

Catégorie détectée : {category}

Réponds avec ce JSON exact :
{{
  "type_attaque": "nom court",
  "severite": "CRITIQUE|HAUTE|MOYENNE|FAIBLE",
  "ip_source": "IP ou null",
  "action": "action recommandée en 1 phrase",
  "nouvelle_regle_necessaire": true,
  "niveau_regle": 12,
  "parent_sid": "{alert.get('rule',{}).get('id','5760')}",
  "description_regle": "LLM: description courte sans guillemets speciaux"
}}

Règles :
- niveau_regle : entier entre 8 et 15
- parent_sid : ID de la règle Wazuh parente (celle de l'alerte)
- description_regle : texte simple, sans apostrophes ni guillemets
- nouvelle_regle_necessaire : TOUJOURS true pour la première alerte de cette catégorie
- niveau_regle : entre 8 et 14 selon la sévérité"""

    try:
        resp = client.messages.create(
            model=MODEL,
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}]
        )
        text = resp.content[0].text.strip()
        # Nettoie les backticks si présents
        if "```" in text:
            parts = text.split("```")
            for part in parts:
                part = part.strip()
                if part.startswith("json"):
                    part = part[4:].strip()
                if part.startswith("{"):
                    text = part
                    break
        return json.loads(text.strip())
    except Exception as e:
        print(f"  [!] Erreur LLM : {e}")
        return None

def build_xml(category: str, level: int, parent_sid: str, description: str) -> str:
    """
    Construit le XML à partir du template — garantit la validité Wazuh
    """
    rid = next_rule_id()
    # Parent SID correct par catégorie
    PARENT_SIDS = {
        "brute_force_ssh":    "5763",
        "nmap_scan":          "4100",
        "auth_failure":       "5503",
        "web_attack":         "31151",
        "dos_attack":         "40113",
        "privilege_escalation": "5402",
        "rootcheck":          "510",
        "default":            "1002",
    }
    parent_sid = PARENT_SIDS.get(category, "1002")
    template = TEMPLATES.get(category, TEMPLATES["default"])
    
    # Nettoie la description
    description = description.replace('"', '').replace("'", '').replace('<', '').replace('>', '')
    if not description:
        description = f"LLM: Detection {category}"

    # Tronque proprement sur une frontière de mot (evite "...tentative es")
    if len(description) > 100:
        description = description[:100].rsplit(' ', 1)[0]

    return template.format(
        id=rid,
        rule_id=rid,
        level=max(8, min(15, level)),
        parent_sid=parent_sid,
        description=description
    )

def deploy(xml_str: str, category: str) -> bool:
    # Anti-doublon par hash
    h = hashlib.md5(xml_str.encode()).hexdigest()
    if h in deployed_hashes:
        print(f"  (règle identique déjà déployée)")
        return False
    deployed_hashes.add(h)

    # Validation Python
    try:
        ET.fromstring(xml_str)
    except ET.ParseError as e:
        print(f"  [!] XML invalide : {e}")
        deployed_hashes.discard(h)
        return False

    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"llm_{category}_{ts}.xml"
    local = os.path.join(RULES_DIR, fname)
    wazuh_dest = os.path.join(WAZUH_RULES, fname)

    with open(local, "w") as f:
        f.write(xml_str)

    # Copie vers Wazuh
    proc = subprocess.Popen(
        ["sudo", "tee", wazuh_dest],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    _, err = proc.communicate(input=xml_str.encode())
    if proc.returncode != 0:
        print(f"  [!] Erreur copie : {err.decode()}")
        os.remove(local)
        deployed_hashes.discard(h)
        return False

    # Test Wazuh
    test = subprocess.run(
        ["sudo", "/var/ossec/bin/wazuh-analysisd", "-t"],
        capture_output=True, text=True
    )
    errors = test.stderr + test.stdout
    if "CRITICAL" in errors:
        for line in errors.split("\n"):
            if "ERROR" in line or "CRITICAL" in line:
                print(f"  [Wazuh] {line.strip()}")
        print(f"  [!] Rejetée — supprimée")
        subprocess.run(["sudo","rm","-f",wazuh_dest], capture_output=True)
        os.remove(local)
        deployed_hashes.discard(h)
        return False

    # Redémarre Wazuh
    subprocess.run(["sudo","systemctl","restart","wazuh-manager"], capture_output=True)
    print(f"  Regle deployee : {fname}")

    # La règle est déjà dans RULES_DIR (~/pfe_soc/rules/custom/) qui est versionné
    # par le dépôt Git racine — commit + push automatiques
    try:
        os.chdir(os.path.expanduser("~/pfe_soc"))
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

    # Ignore toutes les alertes générées par nos règles LLM (>= 100050)
    try:
        if int(rule_id) >= 100050:
            return
    except:
        pass

    # Ignore aussi les groupes llm_generated
    if "llm_generated" in str(alert.get("rule",{}).get("groups",[])):
        return

    # Ignore trafic loopback
    srcip = alert.get("data", {}).get("srcip", "")
    if srcip in ("127.0.0.1", "::1", ""):
        return

    category = get_category(rule_id)
    # Clé = catégorie uniquement (pas IP)
    # 1 seule règle LLM par catégorie d'attaque, quelle que soit l'IP source
    key = (category,)

    if key in seen:
        return

    # Vérifie aussi si une règle LLM pour cette catégorie existe déjà dans Wazuh
    llm_files = [f for f in os.listdir("/var/ossec/etc/rules/")
                 if f.startswith(f"llm_{category}_") and f.endswith(".xml")]
    if llm_files:
        seen.add(key)
        save_seen(seen)
        return

    seen.add(key)
    save_seen(seen)  # Persistance anti-doublon

    print(f"\n[LLM] Analyse alerte niveau {level} — {desc}")
    print(f"  Categorie : {category} | IP : {srcip}")

    result = ask_llm(alert, category)
    if not result:
        return

    print(f"  Type      : {result.get('type_attaque','?')}")
    print(f"  Severite  : {result.get('severite','?')}")
    print(f"  Action    : {result.get('action','?')}")

    # Human-in-the-Loop : réponse graduée selon sévérité
    severite = result.get("severite", "")
    if srcip and srcip not in ("local", "", "127.0.0.1", "::1"):
        if severite == "CRITIQUE":
            # Blocage temporaire 1h + validation SOC requise
            try:
                import subprocess, threading
                subprocess.run(
                    ["sudo", "iptables", "-I", "INPUT", "-s", srcip, "-j", "DROP"],
                    capture_output=True
                )
                print(f"  [AUTO-BLOCK] CRITIQUE — IP {srcip} bloquée 1h")
                print(f"  [VALIDATION] Analyste SOC doit valider via email")
                # Déblocage automatique après 3600s — processus bash détaché
                subprocess.Popen(
                    f'sleep 3600 && sudo iptables -D INPUT -s {srcip} -j DROP',
                    shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                print(f"  [AUTO-UNBLOCK] Déblocage planifié dans 60 min")
            except Exception as e:
                print(f"  [WARN] Blocage auto échoué: {e}")
        elif severite == "HAUTE":
            # Blocage temporaire 15 min, pas de validation requise
            try:
                import subprocess, threading
                subprocess.run(
                    ["sudo", "iptables", "-I", "INPUT", "-s", srcip, "-j", "DROP"],
                    capture_output=True
                )
                print(f"  [AUTO-BLOCK] HAUTE — IP {srcip} bloquée 15 min")
                # Déblocage automatique après 900s — processus bash détaché
                subprocess.Popen(
                    f'sleep 900 && sudo iptables -D INPUT -s {srcip} -j DROP',
                    shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                print(f"  [AUTO-UNBLOCK] Déblocage planifié dans 15 min")
            except Exception as e:
                print(f"  [WARN] Blocage auto échoué: {e}")
        else:
            # MOYENNE/FAIBLE — notification email uniquement
            print(f"  [INFO] {severite} — Email envoyé, pas de blocage auto")

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps({
            "ts": datetime.now().isoformat(),
            "category": category,
            "rule_id": rule_id,
            "level": level,
            "srcip": srcip,
            "analyse": {
                "type_attaque": result.get("type_attaque"),
                "severite": result.get("severite"),
                "action": result.get("action"),
            },
            "rule_generated": result.get("nouvelle_regle_necessaire", False)
        }, ensure_ascii=False) + "\n")

    if result.get("nouvelle_regle_necessaire", False):
        xml = build_xml(
            category=category,
            level=int(result.get("niveau_regle", 12)),
            parent_sid=str(result.get("parent_sid", rule_id)),
            description=result.get("description_regle", f"LLM: {category} detected")
        )
        print(f"  Generation regle XML (template {category})...")
        rule_filename = f"llm_{category}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        deploy(xml, category)
        # Email automatique ingenieur SOC
        if EMAIL_ENABLED:
            try:
                # Détermine l'action automatique effectuée
                sev = result.get("severite", "")
                if sev == "CRITIQUE":
                    auto_act = f"IP {srcip} bloquee automatiquement pendant 60 minutes (severite CRITIQUE)"
                elif sev == "HAUTE":
                    auto_act = f"IP {srcip} bloquee automatiquement pendant 15 minutes (severite HAUTE)"
                else:
                    auto_act = "Aucune action automatique - notification uniquement"

                send_attack_report({
                    "timestamp": datetime.now().isoformat(),
                    "category": category,
                    "attack_type": result.get("type_attaque", category),
                    "severity": result.get("severite", "HAUTE"),
                    "srcip": srcip,
                    "description": alert.get("rule", {}).get("description", ""),
                    "action": result.get("action", ""),
                    "rule_file": rule_filename,
                    "auto_action": auto_act
                })
                print(f"  [EMAIL] Rapport envoye a l ingenieur SOC")
            except Exception as e:
                print(f"  [EMAIL] Erreur: {e}")
    else:
        print(f"  (pas de nouvelle regle necessaire)")

# ── Main ─────────────────────────────────────────────────────────────────────
print(f"[{datetime.now()}] LLM Analyst v3 FINAL demarre")
print(f"Surveillance : {ALERTS_FILE} | niveau >= {MIN_LEVEL}")
print(f"Categories : {list(ATTACK_CATEGORIES.keys())}")
load_existing()
print()

seen_alerts = set()
last_alert_time = time.time()
idle_notified   = False

import os
last_size = os.path.getsize(ALERTS_FILE) if os.path.exists(ALERTS_FILE) else 0

while True:
    try:
        current_size = os.path.getsize(ALERTS_FILE) if os.path.exists(ALERTS_FILE) else 0
        if current_size < last_size:
            print("  [INFO] Fichier alertes réinitialisé - repositionnement")
            last_size = 0

        with open(ALERTS_FILE, "r") as f:
            f.seek(last_size)
            new_content = f.read()
            last_size = f.tell()

        if new_content:
            for line in new_content.splitlines():
                if not line.strip():
                    continue
                try:
                    alert = json.loads(line.strip())
                    process(alert)
                except Exception:
                    continue

        time.sleep(0.5)
    except Exception as e:
        print(f"  [WARN] Erreur lecture: {e}")
        time.sleep(2)

if False:  # dead code pour garder la syntaxe
 with open(ALERTS_FILE, "r") as f:
    f.seek(0, 2)
    while True:
        line = f.readline()
        if not line:
            idle = time.time() - last_alert_time
            if idle > INACTIVITY_TIMEOUT and not idle_notified:
                print(f"  [IDLE] Aucune alerte depuis {int(idle)}s — en attente...")
                idle_notified = True
            time.sleep(0.3)
            continue
        try:
            alert = json.loads(line.strip())
            aid   = alert.get("id","")
            if aid in seen_alerts:
                continue
            seen_alerts.add(aid)
            last_alert_time = time.time()
            idle_notified   = False
            process(alert)
        except Exception:
            continue
