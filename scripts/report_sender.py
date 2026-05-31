#!/usr/bin/env python3
"""
Systeme de rapport d'attaque pour ingenieur SOC
Envoie un email HTML structure apres chaque detection critique
"""
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# ============================================================
# CONFIGURATION EMAIL — valeurs chargées depuis .env
# (systemd les injecte via EnvironmentFile ; voir .env.example)
# ============================================================
SMTP_HOST  = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT  = int(os.environ.get("SMTP_PORT", "587"))
EMAIL_FROM = os.environ.get("EMAIL_FROM", "")
EMAIL_PASS = os.environ.get("EMAIL_PASS", "")   # Mot de passe d'application Gmail (jamais en dur)
EMAIL_TO   = os.environ.get("EMAIL_TO", EMAIL_FROM)

# Seulement envoyer pour ces severites
ALERT_SEVERITIES = {"CRITIQUE", "HAUTE"}

def send_attack_report(detection: dict) -> bool:
    """Envoie un rapport structure a l'ingenieur SOC"""

    severity    = detection.get('severity', 'INCONNUE')
    category    = detection.get('category', 'unknown')
    attack_type = detection.get('attack_type', 'Inconnu')
    srcip       = detection.get('srcip', 'N/A')
    action      = detection.get('action', '')
    rule_file   = detection.get('rule_file', '')
    timestamp   = detection.get('timestamp', datetime.now().isoformat())
    description = detection.get('description', '')

    # Filtre par severite
    if severity not in ALERT_SEVERITIES:
        return False

    severity_color = {
        'CRITIQUE': '#dc3545',
        'HAUTE':    '#fd7e14',
        'MOYENNE':  '#0dcaf0',
        'BASSE':    '#198754'
    }.get(severity, '#6c757d')

    severity_emoji = {
        'CRITIQUE': 'CRITIQUE',
        'HAUTE':    'HAUTE',
        'MOYENNE':  'MOYENNE',
        'BASSE':    'BASSE'
    }.get(severity, severity)

    subject = f"[SOC ALERT] {severity_emoji} | {attack_type} depuis {srcip}"

    html_body = f"""<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8"></head>
<body style="font-family:Arial,sans-serif;background:#f0f2f5;margin:0;padding:20px">
<div style="max-width:680px;margin:0 auto;background:white;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.15)">

  <!-- HEADER -->
  <div style="background:#0d1b2a;padding:28px 30px;text-align:center">
    <h1 style="color:#00d4ff;margin:0;font-size:1.4rem">
      SOC Alert - AI Detection as Code
    </h1>
    <p style="color:#8892b0;margin:8px 0 0;font-size:0.9rem">
      Rapport automatique genere par Claude AI - PFE 2026
    </p>
  </div>

  <!-- SEVERITY BANNER -->
  <div style="background:{severity_color};padding:16px;text-align:center">
    <span style="color:white;font-size:1.2rem;font-weight:bold;letter-spacing:1px">
      SEVERITE : {severity}
    </span>
  </div>

  <!-- INCIDENT DETAILS -->
  <div style="padding:30px">
    <h2 style="color:#0d1b2a;margin:0 0 20px;font-size:1.1rem;border-bottom:2px solid #00d4ff;padding-bottom:10px">
      Details de l'incident
    </h2>

    <table style="width:100%;border-collapse:collapse">
      <tr style="background:#f8f9fa">
        <td style="padding:12px 15px;font-weight:bold;color:#495057;width:38%;border-bottom:1px solid #dee2e6">
          Timestamp
        </td>
        <td style="padding:12px 15px;color:#212529;border-bottom:1px solid #dee2e6">
          {timestamp[:19].replace('T', ' ')}
        </td>
      </tr>
      <tr>
        <td style="padding:12px 15px;font-weight:bold;color:#495057;border-bottom:1px solid #dee2e6">
          Type d'attaque
        </td>
        <td style="padding:12px 15px;color:#212529;font-weight:bold;border-bottom:1px solid #dee2e6">
          {attack_type}
        </td>
      </tr>
      <tr style="background:#f8f9fa">
        <td style="padding:12px 15px;font-weight:bold;color:#495057;border-bottom:1px solid #dee2e6">
          Categorie
        </td>
        <td style="padding:12px 15px;color:#212529;border-bottom:1px solid #dee2e6">
          {category}
        </td>
      </tr>
      <tr>
        <td style="padding:12px 15px;font-weight:bold;color:#495057;border-bottom:1px solid #dee2e6">
          IP Source
        </td>
        <td style="padding:12px 15px;font-family:monospace;font-size:1.1rem;color:#dc3545;font-weight:bold;border-bottom:1px solid #dee2e6">
          {srcip}
        </td>
      </tr>
      <tr style="background:#f8f9fa">
        <td style="padding:12px 15px;font-weight:bold;color:#495057;border-bottom:1px solid #dee2e6">
          Description Wazuh
        </td>
        <td style="padding:12px 15px;color:#212529;border-bottom:1px solid #dee2e6">
          {description}
        </td>
      </tr>
      <tr>
        <td style="padding:12px 15px;font-weight:bold;color:#495057">
          Regle LLM deployee
        </td>
        <td style="padding:12px 15px;font-family:monospace;color:#198754">
          {rule_file}
        </td>
      </tr>
    </table>

    <!-- ACTION RECOMMENDED -->
    <div style="background:#fff8e1;border-left:4px solid #ffc107;border-radius:0 8px 8px 0;padding:18px;margin-top:25px">
      <p style="color:#856404;font-weight:bold;margin:0 0 8px;font-size:0.95rem">
        Action recommandee par l'IA (Claude API)
      </p>
      <p style="color:#533f03;margin:0;line-height:1.7;font-size:0.9rem">
        {action}
      </p>
    </div>

    <!-- PIPELINE STATUS -->
    <div style="background:#e8f5e9;border-left:4px solid #4caf50;border-radius:0 8px 8px 0;padding:18px;margin-top:18px">
      <p style="color:#1b5e20;font-weight:bold;margin:0 0 10px;font-size:0.95rem">
        Pipeline Detection as Code - Etapes executees
      </p>
      <table style="width:100%;font-size:0.85rem">
        <tr>
          <td style="padding:4px 0;color:#2e7d32">OK</td>
          <td style="padding:4px 8px;color:#212529">Wazuh a detecte l'attaque en temps reel</td>
        </tr>
        <tr>
          <td style="padding:4px 0;color:#2e7d32">OK</td>
          <td style="padding:4px 8px;color:#212529">Claude AI a analyse et classifie la menace</td>
        </tr>
        <tr>
          <td style="padding:4px 0;color:#2e7d32">OK</td>
          <td style="padding:4px 8px;color:#212529">Regle XML generee et versionnee sur GitHub</td>
        </tr>
        <tr>
          <td style="padding:4px 0;color:#2e7d32">OK</td>
          <td style="padding:4px 8px;color:#212529">GitHub Actions - Validation syntaxe XML</td>
        </tr>
        <tr>
          <td style="padding:4px 0;color:#2e7d32">OK</td>
          <td style="padding:4px 8px;color:#212529">Deploiement automatique sur Wazuh (self-hosted runner)</td>
        </tr>
        <tr>
          <td style="padding:4px 0;color:#2e7d32">OK</td>
          <td style="padding:4px 8px;color:#212529">Ce rapport envoye automatiquement a l'ingenieur SOC</td>
        </tr>
      </table>
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
      Claude API (claude-sonnet-4-5) | Wazuh v4.7.5 | GitHub Actions CI/CD
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
    # Test avec une fausse alerte
    test = {
        'timestamp':   datetime.now().isoformat(),
        'category':    'brute_force_ssh',
        'attack_type': 'Brute Force SSH',
        'severity':    'CRITIQUE',
        'srcip':       '192.168.1.139',
        'description': 'sshd: brute force trying to get access to the system',
        'action':      "Bloquer immediatement l'IP 192.168.1.139 au niveau du firewall et auditer le compte root pour verifier toute compromission.",
        'rule_file':   'llm_brute_force_ssh_test.xml'
    }
    print("Envoi du rapport test...")
    result = send_attack_report(test)
    print("Succes !" if result else "Echec - verifie EMAIL_PASS dans le fichier")
