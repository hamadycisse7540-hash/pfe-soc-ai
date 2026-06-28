# PFE SOC — AI Empowered Detection as Code
## Contexte pour Claude Code (rédaction mémoire)

### Identité
- Titre : AI Empowered Detection as Code for Advanced and Time-Efficient Threat Detection in a SOC Environment
- Étudiant : Stage NUMEA
- GitHub : https://github.com/[username]/pfe-soc-ai
- Email : [email confidentiel]

### Infrastructure
- Ubuntu 22.04 Manager : 192.168.1.132 — Wazuh v4.7.5
- Kali Linux Agent 001 : 192.168.1.158 (DHCP dynamique)
- Dashboard Wazuh : https://192.168.1.132
- API Flask SOC : http://192.168.1.132:8080
- Dashboard IPs SOC : http://192.168.1.132:8080/dashboard

### Pipeline complet (Detection as Code)
Attaque Kali → Wazuh (règles statiques) → alerts.json
→ llm_analyst_v3.py surveille alerts.json (tail -f)
→ Claude API claude-sonnet-4-6 (~4s) → classification
→ CRITIQUE: iptables DROP 60min (Popen bash) + Email SOC
→ HAUTE: iptables DROP 15min + Email SOC
→ MOYENNE/FAIBLE: Email SOC uniquement
→ Règle XML générée via template → wazuh-analysisd -t
→ restart wazuh-manager → GitHub commit
→ CI/CD deploy.yml → self-hosted runner → Wazuh

### Fichiers clés
- llm_analyst_v3.py : moteur LLM + Human-in-the-Loop SOAR
- nmap_watcher.py : détection Nmap via kern.log (IPs Kali dynamiques)
- flask_api.py : API REST (port 8080) + routes dashboard
- soc_dashboard.py : HTML dashboard SOC IP Management
- report_sender.py : email HTML enrichi (ipinfo.io, auto_action, boutons)
- inject_alerts.py : injection DoS + PrivEsc (scénarios simulés)
- start_demo.sh : reset complet + démo 6 scénarios
- rules/custom/ : 8 règles statiques Wazuh
- .github/workflows/deploy.yml : CI/CD validate + deploy

### Règles statiques (8 fichiers, 16 IDs, MITRE ATT&CK)
100009: SSH Invalid user → T1110.003
100002: Nmap scan iptables freq=18/45s → T1046
100010: SSH Failed password → T1110.001
100003: Brute Force SSH 8 échecs/120s (chaîne 100010) → T1110
100004: SQL Injection sqlmap/UNION SELECT → T1190
100005: Web Scanner nikto/sqlmap → T1595.003
100006: Sudo root USER=root (!ubuntu) → T1548.003
100007: Auth failure PAM → T1110
100008: New user useradd/adduser → T1136.001

### Catégories LLM (6 + default)
brute_force_ssh, nmap_scan, web_attack, rootcheck, dos_attack, privilege_escalation

### Anti-doublon
- Clé = (category,) → 1 règle LLM par catégorie par session
- Cache : .seen_categories.json
- Vérification fichiers llm_{category}_*.xml existants
- Reset : rm -f .seen_categories.json avant démo

### Démo validée (18 juin 2026, session 00:27-00:50)
Nmap scan      : 22s HAUTE    T1046
Hydra SSH      : 20s CRITIQUE T1110
Nikto CGI      : 23s HAUTE    T1190
Shellshock     : 39s CRITIQUE T1059
DoS SYN flood  : 25s CRITIQUE T1498
PrivEsc sudo   : 25s CRITIQUE T1548
MOYENNE = 26 secondes (alerte → règle + email + GitHub)

### Services systemd (7 actifs)
wazuh-indexer, wazuh-manager, wazuh-dashboard, filebeat
pfe-llm-analyst, pfe-nmap-watcher, pfe-flask-api

### Human-in-the-Loop SOAR
CRITIQUE → iptables -I INPUT -s IP -j DROP (60min) + Email + Règle XML
HAUTE    → iptables -I INPUT -s IP -j DROP (15min) + Email + Règle XML
MOYENNE  → Email + Règle XML
Déblocage → API Flask POST /api/unblock/<ip> ou auto après timeout

### Structure mémoire LaTeX (4 chapitres + 8 annexes)
Ch1: Contexte et problématique SOC
Ch2: État de l'art (SIEM, LLM, Detection as Code, SOAR)
Ch3: Conception de la solution
Ch4: Développement et validation (6 scénarios, résultats, métriques)
Annexe A: Architecture complète
Annexe B: Configuration Wazuh (ossec.conf, services systemd)
Annexe C: Règles Detection as Code (statiques + LLM)
Annexe D: Logs analysés (SSH, Nmap, JSON alertes)
Annexe E: Code source (lecture alertes, Claude API, build_xml)
Annexe F: Workflow GitHub Actions (deploy.yml)
Annexe G: Résultats expérimentaux (tableau 6 scénarios, délais)
Annexe H: Captures dashboard Wazuh

### Points forts soutenance
1. 26s en moyenne : alerte → règle déployée dans Wazuh
2. Human-in-the-Loop SOAR : automatisation graduée + contrôle humain
3. Detection as Code : versionnement GitHub + CI/CD
4. MITRE ATT&CK : mapping complet
5. Anti-doublon : 1 règle LLM par catégorie

### Limitations documentées (à mentionner à l'oral)
- Catégorie "default" fourre-tout (Shellshock + autres non catégorisés)
- Popen bash pour déblocage (vs firewall-cmd --timeout en prod)
- Email simple (vs ticket ITSM ServiceNow/Jira en prod)
- Pas de SOAR commercial (Shuffle, Cortex XSOAR, Splunk SOAR)
- Agent Wazuh sur manager lui-même = active response graphique limitée
