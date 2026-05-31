#!/usr/bin/env python3
"""
PFE SOC – LLM Analyst v2 (anti-doublons)
"""
import json, os, time, subprocess
from datetime import datetime
import anthropic

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
RULES_DIR   = os.path.expanduser("~/pfe_soc/github/rules/custom")
LOG_FILE    = os.path.expanduser("~/pfe_soc/llm_analysis.log")
MODEL       = "claude-3-haiku-20240307"

# Cache des signatures déjà traitées
SEEN_ATTACKS = set()

# Initialisation du client Anthropic
client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

def already_seen(alert: dict) -> bool:
    """
    Construit une signature à partir du type d'attaque et de l'IP source.
    Si elle a déjà été traitée, on ignore.
    """
    rule_desc = alert.get("rule", {}).get("description", "")
    src_ip    = alert.get("data", {}).get("srcip", "unknown")
    sig = f"{rule_desc[:40]}|{src_ip}"
    if sig in SEEN_ATTACKS:
        return True
    SEEN_ATTACKS.add(sig)
    return False

def generate_rule(alert: dict) -> dict:
    """Envoie l'alerte au LLM et retourne l'analyse + la règle XML"""
    alert_json = json.dumps(alert, indent=2, ensure_ascii=False)
    prompt = f"""Tu es un analyste SOC expert en Wazuh.
Voici une alerte :

{alert_json}

Analyse-la et retourne uniquement un JSON valide avec :
{{
  "type_attaque": "...",
  "severite": "CRITIQUE|HAUTE|MOYENNE|FAIBLE",
  "ip_source": "...",
  "description": "...",
  "action_recommandee": "...",
  "regle_wazuh_xml": "<group>...</group>"
}}

La règle XML doit être une règle Wazuh valide, avec un ID entre 100000 et 120000,
un niveau approprié (12 à 15 pour les attaques critiques), et utiliser les champs
if_sid, match ou regex pour détecter ce type d'attaque.

Ne mets aucun texte avant ou après le JSON.
"""
    resp = client.messages.create(
        model=MODEL,
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}]
    )
    raw = resp.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1]
        if raw.endswith("```"):
            raw = raw[:-3]
    return json.loads(raw)

def deploy_rule(filepath: str, filename: str) -> bool:
    """Copie la règle sur Wazuh et redémarre le manager"""
    wazuh_path = f"/var/ossec/etc/rules/{filename}"
    try:
        with open(filepath) as f:
            rule_content = f.read()
        proc = subprocess.Popen(
            ["sudo", "tee", wazuh_path],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE
        )
        _, stderr = proc.communicate(input=rule_content.encode())
        if proc.returncode == 0:
            subprocess.run(["sudo", "systemctl", "restart", "wazuh-manager"], check=True)
            print(f"  Règle déployée : {wazuh_path}")
            return True
        else:
            print(f"  Erreur déploiement : {stderr.decode()}")
            return False
    except Exception as e:
        print(f"  Exception : {e}")
        return False

def main():
    if not os.path.exists(ALERTS_FILE):
        print("Fichier alerts.json introuvable")
        return

    print(f"[{datetime.now()}] LLM Analyst v2 démarré (anti-doublons)")
    print(f"Surveillance : {ALERTS_FILE}")
    print(f"Analyse uniquement les alertes niveau >= 8\n")

    with open(ALERTS_FILE, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            try:
                alert = json.loads(line.strip())
                level = alert.get("rule", {}).get("level", 0)
                if level < 8:
                    continue

                # Vérification anti-doublon
                if already_seen(alert):
                    continue

                # Génération de la règle
                print(f"\n[LLM] Analyse alerte niveau {level} — {alert['rule']['description'][:50]}")
                analysis = generate_rule(alert)
                print(f"  Type      : {analysis.get('type_attaque')}")
                print(f"  Sévérité  : {analysis.get('severite')}")
                print(f"  IP source : {analysis.get('ip_source')}")
                print(f"  Action    : {analysis.get('action_recommandee')}")

                # Sauvegarde de la règle
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                rule_xml = analysis.get("regle_wazuh_xml", "")
                if not rule_xml:
                    print("  Le LLM n'a pas fourni de règle XML.")
                    continue

                filename = f"llm_generated_{ts}.xml"
                filepath = os.path.join(RULES_DIR, filename)
                with open(filepath, "w") as f:
                    f.write(rule_xml)
                print(f"  Règle sauvegardée : {filename}")

                # Vérification syntaxe XML rapide
                import xml.etree.ElementTree as ET
                try:
                    ET.fromstring(rule_xml)
                    print("  Syntaxe XML valide")
                except ET.ParseError as e:
                    print(f"  Erreur XML : {e}")
                    continue

                # Déploiement
                deploy_rule(filepath, filename)

                # Log de l'analyse
                with open(LOG_FILE, 'a') as log:
                    log.write(json.dumps({
                        "timestamp": datetime.now().isoformat(),
                        "alert_rule_id": alert.get("rule", {}).get("id"),
                        "alert_level": level,
                        "llm_analysis": analysis
                    }) + "\n")

            except Exception as e:
                print(f"  [!] Erreur : {e}")

if __name__ == "__main__":
    main()
