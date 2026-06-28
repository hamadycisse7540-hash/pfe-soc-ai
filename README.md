# PFE SOC — AI Empowered Detection as Code

## Sujet
AI Empowered Detection as Code for Advanced and Time-Efficient Threat Detection in a SOC Environment

## Architecture
Kali Linux (Attaquant)

↓ Nmap / Hydra / Nikto / DoS / PrivEsc

Wazuh Agent v4.7.5

↓ logs temps réel

Wazuh Manager + OpenSearch + Dashboard (192.168.1.132)

↓ alerts.json (surveillance continue)

pfe-llm-analyst.service

↓ Claude API claude-sonnet-4-6 (~4s)

Classification + Réponse graduée :

CRITIQUE → iptables DROP 60min + Email SOC

HAUTE    → iptables DROP 15min + Email SOC

MOYENNE  → Email SOC uniquement

↓

Génération règle XML (MITRE ATT&CK + PCI DSS + GDPR)

↓ commit automatique

GitHub Repository (Detection as Code)

↓

GitHub Actions CI/CD

├── Validate Rules (ubuntu-latest) — xmllint + test_rules.py

└── Deploy to Wazuh (self-hosted runner) — cp + systemctl restart

↓

Email HTML → Ingénieur SOC (ipinfo.io + boutons block/unblock)
## Composants

| Composant | Description |
|-----------|-------------|
| Wazuh Manager v4.7.5 | SIEM - collecte et corrèle les alertes |
| Claude API (claude-sonnet-4-6) | LLM - analyse contextuelle + génération règles |
| pfe-llm-analyst.service | Moteur LLM - surveillance 24h/24 |
| pfe-nmap-watcher.service | Détection scan Nmap via kern.log + iptables |
| pfe-flask-api.service | API REST + Dashboard SOC IP Management (port 8080) |
| GitHub Actions | CI/CD - validation syntaxe XML + déploiement |
| report_sender.py | Email HTML enrichi - ipinfo.io + auto_action + boutons SOC |

## Types d'attaques détectées

| Attaque | Outil Kali | Catégorie | MITRE | Délai moyen |
|---------|-----------|-----------|-------|------------|
| Brute Force SSH | Hydra | brute_force_ssh | T1110 | 20s |
| Scan réseau Nmap | Nmap | nmap_scan | T1046 | 22s |
| Web Attack / CGI | Nikto | web_attack | T1190 | 23s |
| Shellshock CVE-2014-6271 | Nikto | default | T1059 | 39s |
| DoS SYN Flood | Injection | dos_attack | T1498 | 25s |
| Privilege Escalation | sudo/su | privilege_escalation | T1548.003 | 25s |

**Temps moyen de réponse : 26 secondes** (alerte détectée → règle déployée + email + GitHub)

## Règles statiques Wazuh (8 fichiers, 16 IDs)

| ID | Attaque | MITRE |
|----|---------|-------|
| 100009 | SSH Invalid user | T1110.003 |
| 100002 | Nmap scan (freq=18/45s) | T1046 |
| 100010 | SSH Failed password | T1110.001 |
| 100003 | Brute Force SSH (8 échecs/120s) | T1110 |
| 100004 | SQL Injection | T1190 |
| 100005 | Web Scanner (nikto/sqlmap) | T1595.003 |
| 100006 | Sudo root (!ubuntu) | T1548.003 |
| 100007 | Auth failure PAM | T1110 |
| 100008 | New user created | T1136.001 |

## Human-in-the-Loop SOAR
Alerte Wazuh

↓

LLM Analyst (Claude API ~4s)

↓

CRITIQUE → Blocage auto 60min + Email + Règle XML

HAUTE    → Blocage auto 15min + Email + Règle XML

MOYENNE  → Email + Règle XML

↓

Analyste SOC valide via Dashboard ou email

↓

Déblocage : POST /api/unblock/<ip>
## Installation

```bash
# Clone
git clone https://github.com/hamadycisse7540-hash/pfe-soc-ai.git
cd pfe-soc-ai

# Environnement Python
python3 -m venv ~/ml_env
source ~/ml_env/bin/activate
pip install anthropic flask flask-cors

# Variables d'environnement
cp .env.example .env
# Editer .env : ANTHROPIC_API_KEY, EMAIL_FROM, EMAIL_PASS, EMAIL_TO

# Services systemd
sudo cp systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable pfe-llm-analyst pfe-nmap-watcher pfe-flask-api
sudo systemctl start pfe-llm-analyst pfe-nmap-watcher pfe-flask-api
```

## Services systemd

```bash
sudo systemctl status pfe-llm-analyst    # LLM analyst
sudo systemctl status pfe-nmap-watcher   # Nmap detector
sudo systemctl status pfe-flask-api      # Flask API + Dashboard
sudo journalctl -u pfe-llm-analyst -f    # Logs temps réel
```

## API Endpoints (port 8080)

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | /dashboard | Dashboard SOC IP Management |
| GET | /api/stats | Statistiques de détection |
| GET | /api/blocked | IPs bloquées (iptables) |
| GET | /api/top-ips | Top 10 IPs attaquantes |
| GET | /api/rules-count | Règles LLM déployées |
| POST | /api/block/<ip> | Blocage manuel analyste |
| POST | /api/unblock/<ip> | Déblocage analyste SOC |

## Démo complète

```bash
# Reset propre
cd ~/pfe_soc
bash start_demo.sh

# Depuis Kali (séquentiel, 90s entre chaque)
nmap -sS -p 1-1000 192.168.1.132
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.132 -t 4 -I
nikto -h http://192.168.1.132

# Injection DoS + PrivEsc
python3 inject_alerts.py

# Surveillance
sudo journalctl -u pfe-llm-analyst -f
```

## Infrastructure

- Ubuntu Manager : 192.168.1.132 (Wazuh + LLM + Apache + Flask)
- Kali Attaquant : 192.168.1.158 (Agent Wazuh ID 001)
- Dashboard Wazuh : https://192.168.1.132
- SOC Dashboard : http://192.168.1.132:8080/dashboard
- GitHub : https://github.com/hamadycisse7540-hash/pfe-soc-ai
- GitHub Actions : https://github.com/hamadycisse7540-hash/pfe-soc-ai/actions
