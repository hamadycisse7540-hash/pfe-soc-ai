#!/usr/bin/env python3
"""
Systeme de rapport d'attaque pour ingenieur SOC
Envoie un email HTML structure apres chaque detection critique
"""
import os

def _load_env():
    env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.exists(env_file) and not os.environ.get('EMAIL_PASS'):
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    k, v = line.split('=', 1)
                    os.environ.setdefault(k.strip(), v.strip())
_load_env()
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

SMTP_HOST  = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT  = int(os.environ.get("SMTP_PORT", "587"))
EMAIL_FROM = os.environ.get("EMAIL_FROM", "")
EMAIL_PASS = os.environ.get("EMAIL_PASS", "")
EMAIL_TO   = os.environ.get("EMAIL_TO", EMAIL_FROM)
ALERT_SEVERITIES = {"CRITIQUE", "HAUTE"}
FLASK_URL  = "http://192.168.1.132:8080"

def send_attack_report(detection: dict) -> bool:
    severity    = detection.get('severity', 'INCONNUE')
    category    = detection.get('category', 'unknown')
    attack_type = detection.get('attack_type', 'Inconnu')
    srcip       = detection.get('srcip', 'N/A')
    action      = detection.get('action', '')
    rule_file   = detection.get('rule_file', '')
    timestamp   = detection.get('timestamp', datetime.now().isoformat())
    description = detection.get('description', '')
    auto_action = detection.get('auto_action', '')

    if severity not in ALERT_SEVERITIES:
        return False

    severity_color = {
        'CRITIQUE': '#dc3545',
        'HAUTE':    '#fd7e14',
        'MOYENNE':  '#0dcaf0',
        'BASSE':    '#198754'
    }.get(severity, '#6c757d')

    subject = f"[SOC ALERT] {severity} | {attack_type} depuis {srcip}"

    html_body = f"""<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"></head>
<body style="font-family:Arial,sans-serif;background:#f0f2f5;margin:0;padding:20px">
<div style="max-width:680px;margin:0 auto;background:white;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.15)">

  <!-- HEADER -->
  <div style="background:#0d1b2a;padding:28px 30px;text-align:center">
    <h1 style="color:#00d4ff;margin:0;font-size:1.4rem">SOC Alert - AI Detection as Code</h1>
    <p style="color:#8892b0;margin:8px 0 0;font-size:0.9rem">Rapport automatique genere par Claude AI - PFE 2026</p>
  </div>

  <!-- SEVERITY BANNER -->
  <div style="background:{severity_color};padding:16px;text-align:center">
    <span style="color:white;font-size:1.2rem;font-weight:bold;letter-spacing:1px">SEVERITE : {severity}</span>
  </div>

  <!-- WARNING BANNER -->
  <div style="background:#fff3cd;border:1px solid #ffc107;padding:14px 20px;text-align:center">
    <span style="color:#856404;font-weight:bold;font-size:0.95rem">
      ⚠️ Veuillez verifier la legitimite de cette attaque au niveau SOC avant toute action definitive
    </span>
  </div>

  <!-- INCIDENT DETAILS -->
  <div style="padding:30px">
    <h2 style="color:#0d1b2a;margin:0 0 20px;font-size:1.1rem;border-bottom:2px solid #00d4ff;padding-bottom:10px">
      Details de l'incident
    </h2>

    <table style="width:100%;border-collapse:collapse">
      <tr style="background:#f8f9fa">
        <td style="padding:12px 15px;font-weight:bold;color:#495057;width:38%;border-bottom:1px solid #dee2e6">Timestamp</td>
        <td style="padding:12px 15px;color:#212529;border-bottom:1px solid #dee2e6">{timestamp[:19].replace('T', ' ')}</td>
      </tr>
      <tr>
        <td style="padding:12px 15px;font-weight:bold;color:#495057;border-bottom:1px solid #dee2e6">Type d'attaque</td>
        <td style="padding:12px 15px;color:#212529;font-weight:bold;border-bottom:1px solid #dee2e6">{attack_type}</td>
      </tr>
      <tr style="background:#f8f9fa">
        <td style="padding:12px 15px;font-weight:bold;color:#495057;border-bottom:1px solid #dee2e6">Categorie</td>
        <td style="padding:12px 15px;color:#212529;border-bottom:1px solid #dee2e6">{category}</td>
      </tr>
      <tr>
        <td style="padding:12px 15px;font-weight:bold;color:#495057;border-bottom:1px solid #dee2e6">IP Source</td>
        <td style="padding:12px 15px;border-bottom:1px solid #dee2e6">
          <a href="https://ipinfo.io/{srcip}" style="color:#dc3545;font-family:monospace;font-size:1.1rem;font-weight:bold;text-decoration:none">
            {srcip} &#x1F517; (Infos IP)
          </a>
        </td>
      </tr>
      <tr style="background:#f8f9fa">
        <td style="padding:12px 15px;font-weight:bold;color:#495057;border-bottom:1px solid #dee2e6">Description Wazuh</td>
        <td style="padding:12px 15px;color:#212529;border-bottom:1px solid #dee2e6">{description}</td>
      </tr>
      <tr>
        <td style="padding:12px 15px;font-weight:bold;color:#495057;border-bottom:1px solid #dee2e6">Regle LLM deployee</td>
        <td style="padding:12px 15px;font-family:monospace;color:#198754;border-bottom:1px solid #dee2e6">{rule_file}</td>
      </tr>
      <tr style="background:#f8f9fa">
        <td style="padding:12px 15px;font-weight:bold;color:#495057">Action effectuee automatiquement</td>
        <td style="padding:12px 15px;color:#dc3545;font-weight:bold">{auto_action if auto_action else 'Aucune action automatique (severite non critique)'}</td>
      </tr>
    </table>

    <!-- AI RECOMMENDATION -->
    <div style="background:#fff8e1;border-left:4px solid #ffc107;border-radius:0 8px 8px 0;padding:18px;margin-top:25px">
      <p style="color:#856404;font-weight:bold;margin:0 0 8px;font-size:0.95rem">Recommandation IA (Claude API)</p>
      <p style="color:#533f03;margin:0;line-height:1.7;font-size:0.9rem">{action}</p>
    </div>

    <!-- PIPELINE STATUS -->
    <div style="background:#e8f5e9;border-left:4px solid #4caf50;border-radius:0 8px 8px 0;padding:18px;margin-top:18px">
      <p style="color:#1b5e20;font-weight:bold;margin:0 0 10px;font-size:0.95rem">Pipeline Detection as Code - Etapes executees</p>
      <table style="width:100%;font-size:0.85rem">
        <tr><td style="padding:4px 0;color:#2e7d32">✅</td><td style="padding:4px 8px;color:#212529">Wazuh a detecte l'attaque en temps reel</td></tr>
        <tr><td style="padding:4px 0;color:#2e7d32">✅</td><td style="padding:4px 8px;color:#212529">Claude AI a analyse et classifie la menace</td></tr>
        <tr><td style="padding:4px 0;color:#2e7d32">✅</td><td style="padding:4px 8px;color:#212529">Regle XML generee et versionnee sur GitHub</td></tr>
        <tr><td style="padding:4px 0;color:#2e7d32">✅</td><td style="padding:4px 8px;color:#212529">GitHub Actions - Validation syntaxe XML</td></tr>
        <tr><td style="padding:4px 0;color:#2e7d32">✅</td><td style="padding:4px 8px;color:#212529">Deploiement automatique sur Wazuh (self-hosted runner)</td></tr>
        <tr><td style="padding:4px 0;color:#2e7d32">✅</td><td style="padding:4px 8px;color:#212529">Ce rapport envoye automatiquement a l'ingenieur SOC</td></tr>
      </table>
    </div>

    <!-- ACTIONS BUTTONS -->
    <div style="background:#fce4ec;border-left:4px solid #dc3545;border-radius:0 8px 8px 0;padding:18px;margin-top:18px">
      <p style="color:#b71c1c;font-weight:bold;margin:0 0 12px;font-size:0.95rem">Actions disponibles pour l'analyste SOC</p>
      <div style="text-align:center">
        <a href="{FLASK_URL}/api/unblock/{srcip}"
           style="display:inline-block;background:#198754;color:white;padding:11px 22px;border-radius:6px;text-decoration:none;font-size:0.9rem;margin:5px">
           Debloquer l'IP {srcip}
        </a>
        <a href="https://ipinfo.io/{srcip}"
           style="display:inline-block;background:#0d6efd;color:white;padding:11px 22px;border-radius:6px;text-decoration:none;font-size:0.9rem;margin:5px">
           Infos sur l'IP
        </a>
        <a href="{FLASK_URL}/api/blocked"
           style="display:inline-block;background:#6c757d;color:white;padding:11px 22px;border-radius:6px;text-decoration:none;font-size:0.9rem;margin:5px">
           IPs bloquees
        </a>
      </div>
    </div>

    <!-- LINKS -->
    <div style="margin-top:28px;text-align:center">
      <a href="https://github.com/hamadycisse7540-hash/pfe-soc-ai/actions"
         style="display:inline-block;background:#0d1b2a;color:white;padding:11px 22px;border-radius:6px;text-decoration:none;font-size:0.9rem;margin:5px">
        GitHub Actions
      </a>
      <a href="https://github.com/hamadycisse7540-hash/pfe-soc-ai/tree/main/rules/custom"
         style="display:inline-block;background:#00d4ff;color:#0d1b2a;padding:11px 22px;border-radius:6px;text-decoration:none;font-size:0.9rem;font-weight:bold;margin:5px">
        Regles LLM
      </a>
      <a href="https://192.168.1.132"
         style="display:inline-block;background:#198754;color:white;padding:11px 22px;border-radius:6px;text-decoration:none;font-size:0.9rem;margin:5px">
        Dashboard Wazuh
      </a>
    </div>
  </div>

  <!-- FOOTER -->
  <div style="background:#0d1b2a;padding:20px 30px;text-align:center">
    <p style="color:#8892b0;margin:0;font-size:0.8rem;line-height:1.6">
      Genere automatiquement par le systeme SOC AI<br>
      PFE 2026 - AI Empowered Detection as Code<br>
      Claude API (claude-sonnet-4-6) | Wazuh v4.7.5 | GitHub Actions CI/CD
    </p>
  </div>

</div>
</body>
</html>"""

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = EMAIL_FROM
        msg['To']      = EMAIL_TO
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(EMAIL_FROM, EMAIL_PASS)
            server.sendmail(EMAIL_FROM, [EMAIL_TO], msg.as_string())
        print(f"[EMAIL] Rapport envoye : {attack_type} depuis {srcip}")
        return True
    except Exception as e:
        print(f"[EMAIL] Erreur envoi : {e}")
        return False


if __name__ == '__main__':
    test = {
        'timestamp':   datetime.now().isoformat(),
        'category':    'brute_force_ssh',
        'attack_type': 'Brute Force SSH',
        'severity':    'CRITIQUE',
        'srcip':       '192.168.1.158',
        'description': 'BRUTE FORCE SSH - 8 echecs Failed password en 120s',
        'action':      "Bloquer immediatement l'IP 192.168.1.158 au niveau du firewall et auditer le compte root.",
        'rule_file':   'llm_brute_force_ssh_test.xml',
        'auto_action': 'IP 192.168.1.158 bloquee automatiquement pendant 60 minutes (severite CRITIQUE)'
    }
    print("Envoi du rapport test...")
    result = send_attack_report(test)
    print("Succes !" if result else "Echec")
