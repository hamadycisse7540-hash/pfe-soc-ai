# PFE SOC — AI Empowered Detection as Code

## Sujet
**AI Empowered Detection as a Code for an advanced, time efficient and last trending threat detection in a SOC environment**

## Architecture
Kali Linux (Attaquant)
↓ SSH Brute Force / Nmap / Web Attack / DoS / Privilege Escalation
Wazuh Agent v4.7.5
↓ logs temps réel
Wazuh Manager + OpenSearch + Dashboard
↓ alerts.json (surveillance continue)
pfe-llm-analyst.service (Claude API - Anthropic claude-sonnet-4-5)
↓ analyse contextuelle comme un analyste SOC
Génération règle XML Wazuh (avec queries de détection + MITRE ATT&CK)
↓ commit automatique
GitHub Repository (Detection as Code)
↓
GitHub Actions CI/CD
├── Validate Rules (ubuntu-latest) — xmllint + test_rules.py
└── Deploy to Wazuh (self-hosted runner) — cp + systemctl restart
## Composants

| Composant | Description |
|-----------|-------------|
| Wazuh Manager v4.7.5 | SIEM - collecte et corrèle les alertes |
| Claude API (claude-sonnet-4-5) | LLM - analyse et génère les règles |
| pfe-llm-analyst.service | Service systemd - surveillance 24h/24 |
| pfe-nmap-watcher.service | Détection scan Nmap via iptables |
| pfe-soc-dashboard.service | API REST SQLite - stats + blocage IP |
| GitHub Actions | CI/CD - validation syntaxe + déploiement |
| report_sender.py | Email HTML automatique à l'ingénieur SOC |

## Types d'attaques détectées

| Attaque | Outil Kali | Règle MITRE |
|---------|------------|-------------|
| Brute Force SSH | Hydra | T1110 |
| Scan réseau Nmap | Nmap | T1046 |
| Web Attack / Nikto | Nikto | T1190 |
| Shellshock CVE-2014-6271 | Nikto | T1059 |
| DoS SYN Flood | Injection | T1498 |
| Privilege Escalation | sudo/su | T1548.003 |

## Pipeline Detection as Code
Attaque détectée par Wazuh (niveau >= 8)
pfe-llm-analyst lit alerts.json en temps réel
Claude API analyse : type, sévérité, IP source, action
Règle XML générée avec :

frequency + timeframe (corrélation temporelle)
same_source_ip (corrélation par IP)
match/if_matched_sid (query de détection)
MITRE ATT&CK (mapping tactique)
PCI DSS / GDPR compliance tags


Wazuh Manager rechargé automatiquement
Commit GitHub automatique
GitHub Actions : Validate Rules ✅
GitHub Actions : Deploy to Wazuh ✅ (self-hosted runner)
Email rapport HTML → ingénieur SOC
## Installation

```bash
# Clone
git clone https://github.com/hamadycisse7540-hash/pfe-soc-ai.git
cd pfe-soc-ai

# Environnement Python
python3 -m venv ~/ml_env
source ~/ml_env/bin/activate
pip install anthropic flask flask-cors

# Services systemd
sudo cp systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable pfe-llm-analyst pfe-nmap-watcher
sudo systemctl start pfe-llm-analyst pfe-nmap-watcher
```

## Services systemd

```bash
sudo systemctl status pfe-llm-analyst    # LLM analyst
sudo systemctl status pfe-nmap-watcher   # Nmap detector
sudo journalctl -u pfe-llm-analyst -f    # Logs en temps réel
```

## API Endpoints (port 9000)
GET  /api/stats          — Statistiques globales
GET  /api/export/csv     — Export CSV des détections
POST /api/block          — Bloquer une IP (iptables)
DELETE /api/unblock/<ip> — Débloquer une IP
POST /api/ingest         — Ingestion externe
## Infrastructure

- **Ubuntu Manager** : 192.168.1.132 (Wazuh + LLM + Apache)
- **Kali Attaquant** : 192.168.1.139 (Agent Wazuh)
- **GitHub** : https://github.com/hamadycisse7540-hash/pfe-soc-ai
- **GitHub Actions** : https://github.com/hamadycisse7540-hash/pfe-soc-ai/actions
